from __future__ import annotations

import sqlite3
from typing import Any

from .reference_service import search_reference_fingerprints

SEARCH_TYPES = ['auto', 'ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'jarm', 'hassh', 'sni', 'cert_hash', 'ip']


def local_search(conn: sqlite3.Connection, value: str, search_type: str = 'auto', limit: int = 50) -> dict[str, Any]:
    search_value = (value or '').strip()
    if not search_value:
        raise ValueError('Missing search value')
    normalized_type = (search_type or 'auto').strip().lower()
    if normalized_type not in SEARCH_TYPES:
        raise ValueError('Unsupported search type')
    bounded_limit = max(1, min(limit, 200))

    matches: list[dict[str, Any]] = []
    if normalized_type in {'auto', 'ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'jarm', 'hassh'}:
        fp_types = [normalized_type] if normalized_type != 'auto' else ['ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'jarm', 'hassh']
        matches.extend(_fingerprint_matches(conn, search_value, fp_types, bounded_limit))
    if normalized_type in {'auto', 'sni'}:
        matches.extend(_sni_matches(conn, search_value, bounded_limit))
    if normalized_type in {'auto', 'cert_hash'}:
        matches.extend(_cert_matches(conn, search_value, bounded_limit))
    if normalized_type in {'auto', 'ip'}:
        matches.extend(_ip_matches(conn, search_value, bounded_limit))
    if normalized_type in {'auto', 'ja4', 'ja4s', 'ja4h'}:
        reference_type = 'ja4' if normalized_type == 'auto' else normalized_type
        for row in search_reference_fingerprints(conn, fingerprint_value=search_value, fingerprint_type=reference_type, limit=bounded_limit):
            matches.append({
                'match_type': f'reference_{reference_type}',
                'title': (
                    row.get('fingerprint_value') if reference_type == 'ja4'
                    else row.get(f'{reference_type}_fingerprint')
                ) or search_value,
                'subtitle': row.get('application') or row.get('os_name') or 'historical reference',
                'detail': row,
                'provenance': 'reference_historical',
                'sort_bucket': 'reference',
            })

    deduped = []
    seen = set()
    for match in matches:
        key = (match.get('match_type'), match.get('title'), match.get('subtitle'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    deduped.sort(key=_search_sort_key)
    category_counts: dict[str, int] = {}
    for match in deduped:
        category_counts[match.get('match_type') or 'unknown'] = category_counts.get(match.get('match_type') or 'unknown', 0) + 1
    return {
        'search_type': normalized_type,
        'search_value': search_value,
        'count': len(deduped[:bounded_limit]),
        'matches': deduped[:bounded_limit],
        'category_counts': category_counts,
    }


def _fingerprint_matches(conn, value: str, fp_types: list[str], limit: int) -> list[dict[str, Any]]:
    placeholders = ','.join('?' for _ in fp_types)
    rows = conn.execute(
        f"""
        SELECT fp.fingerprint_type, fp.fingerprint_value, fp.provenance, f.id AS flow_id, f.selection_label, s.filename
        FROM fingerprints fp
        JOIN flows f ON f.id = fp.flow_id
        JOIN samples s ON s.id = fp.sample_id
        WHERE fp.fingerprint_value = ? AND fp.fingerprint_type IN ({placeholders})
        ORDER BY f.id DESC
        LIMIT ?
        """,
        [value, *fp_types, limit],
    ).fetchall()
    return [
        {
            'match_type': row['fingerprint_type'],
            'title': row['fingerprint_value'],
            'subtitle': row['selection_label'],
            'detail': {'flow_id': row['flow_id'], 'filename': row['filename']},
            'provenance': row['provenance'],
            'sort_bucket': 'local_flow',
            'sort_flow_id': row['flow_id'],
        }
        for row in rows
    ]


def _sni_matches(conn, value: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT ot.sni, ot.provenance, f.id AS flow_id, f.selection_label, s.filename
        FROM observations_tls ot
        JOIN flows f ON f.id = ot.flow_id
        JOIN samples s ON s.id = f.sample_id
        WHERE lower(ot.sni) = lower(?)
        ORDER BY f.id DESC
        LIMIT ?
        """,
        (value, limit),
    ).fetchall()
    return [
        {
            'match_type': 'sni',
            'title': row['sni'],
            'subtitle': row['selection_label'],
            'detail': {'flow_id': row['flow_id'], 'filename': row['filename']},
            'provenance': row['provenance'],
            'sort_bucket': 'local_flow',
            'sort_flow_id': row['flow_id'],
        }
        for row in rows
    ]


def _cert_matches(conn, value: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT leaf_sha256, spki_sha256, subject_dn, issuer_dn, provenance, flow_id
        FROM certificates
        WHERE lower(leaf_sha256) = lower(?) OR lower(spki_sha256) = lower(?)
        ORDER BY id DESC
        LIMIT ?
        """,
        (value, value, limit),
    ).fetchall()
    results = []
    for row in rows:
        flow = conn.execute('SELECT selection_label FROM flows WHERE id = ?', (row['flow_id'],)).fetchone()
        results.append({
            'match_type': 'cert_hash',
            'title': row['leaf_sha256'] or row['spki_sha256'],
            'subtitle': flow['selection_label'] if flow else row['subject_dn'] or 'certificate',
            'detail': {'subject_dn': row['subject_dn'], 'issuer_dn': row['issuer_dn'], 'flow_id': row['flow_id']},
            'provenance': row['provenance'],
            'sort_bucket': 'local_flow',
            'sort_flow_id': row['flow_id'],
        })
    return results


def _ip_matches(conn, value: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, selection_label, src_ip, dst_ip, protocol
        FROM flows
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (value, value, limit),
    ).fetchall()
    return [
        {
            'match_type': 'ip',
            'title': value,
            'subtitle': row['selection_label'],
            'detail': {'flow_id': row['id'], 'src_ip': row['src_ip'], 'dst_ip': row['dst_ip'], 'protocol': row['protocol']},
            'provenance': 'pcap_observed',
            'sort_bucket': 'local_flow',
            'sort_flow_id': row['id'],
        }
        for row in rows
    ]


def _search_sort_key(match: dict[str, Any]) -> tuple[int, int, str, str]:
    bucket = match.get('sort_bucket') or ('reference' if match.get('provenance') == 'reference_historical' else 'other')
    bucket_rank = {
        'local_flow': 0,
        'other': 1,
        'reference': 2,
    }.get(bucket, 9)
    flow_id = int((match.get('detail') or {}).get('flow_id') or 0)
    return (bucket_rank, -flow_id, str(match.get('match_type') or ''), str(match.get('title') or ''))
