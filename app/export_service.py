from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .flow_detail_service import get_flow_detail
from .reference_service import search_reference_fingerprints


def create_export(
    conn,
    output_dir: Path,
    scope: str,
    export_format: str,
    flow_id: int | None = None,
    search_value: str | None = None,
    search_type: str | None = None,
) -> dict[str, Any]:
    scope = (scope or '').strip().lower()
    export_format = (export_format or '').strip().lower()
    if scope not in {'selected_conversation', 'search_results', 'all'}:
        raise ValueError('Unsupported export scope')
    if export_format not in {'csv', 'json'}:
        raise ValueError('Unsupported export format')

    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = _resolve_run_id(conn, scope=scope, flow_id=flow_id)
    filter_summary = {
        'scope': scope,
        'flow_id': flow_id,
        'search_value': search_value,
        'search_type': search_type,
    }

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    filename = f"ja-bench-{scope}-{timestamp}.{export_format}"
    output_path = output_dir / filename

    if scope == 'selected_conversation':
        if flow_id is None:
            raise ValueError('Selected conversation export requires flow_id')
        detail = get_flow_detail(conn, flow_id)
        if detail is None:
            raise ValueError('Flow not found for export')
        if export_format == 'json':
            output_path.write_text(json.dumps(detail, indent=2, sort_keys=True), encoding='utf-8')
        else:
            _write_csv(output_path, _selected_flow_csv_rows(detail))
    elif scope == 'search_results':
        if not search_value:
            raise ValueError('Search results export requires search_value')
        matches = search_reference_fingerprints(
            conn,
            fingerprint_value=search_value,
            fingerprint_type=(search_type or None),
            limit=500,
        )
        payload = {
            'scope': scope,
            'search_type': search_type,
            'search_value': search_value,
            'count': len(matches),
            'matches': matches,
        }
        if export_format == 'json':
            output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
        else:
            _write_csv(output_path, matches)
    else:
        rows = _all_flow_summary_rows(conn)
        if export_format == 'json':
            payload = {
                'scope': scope,
                'generated_at': timestamp,
                'rows': rows,
            }
            output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
        else:
            _write_csv(output_path, rows)

    cur = conn.execute(
        """
        INSERT INTO exports (run_id, scope, format, filter_summary_json, output_path)
        VALUES (?, ?, ?, ?, ?)
        """,
        (run_id, scope, export_format, json.dumps(filter_summary), str(output_path)),
    )

    return {
        'export_id': cur.lastrowid,
        'scope': scope,
        'format': export_format,
        'output_path': str(output_path),
        'filename': filename,
    }


def _resolve_run_id(conn, scope: str, flow_id: int | None) -> int:
    if scope == 'selected_conversation' and flow_id is not None:
        row = conn.execute(
            """
            SELECT s.run_id
            FROM flows f
            JOIN samples s ON s.id = f.sample_id
            WHERE f.id = ?
            """,
            (flow_id,),
        ).fetchone()
        if row:
            return row['run_id']

    row = conn.execute('SELECT id FROM runs ORDER BY id DESC LIMIT 1').fetchone()
    if not row:
        raise ValueError('No run available yet for export')
    return row['id']


def _selected_flow_csv_rows(detail: dict[str, Any]) -> list[dict[str, Any]]:
    flow = detail.get('flow') or {}
    rows: list[dict[str, Any]] = []
    rows.append({
        'record_type': 'flow',
        'flow_id': flow.get('id'),
        'protocol': flow.get('protocol'),
        'transport': flow.get('transport'),
        'src_ip': flow.get('src_ip'),
        'src_port': flow.get('src_port'),
        'dst_ip': flow.get('dst_ip'),
        'dst_port': flow.get('dst_port'),
        'selection_label': flow.get('selection_label'),
        'packet_count': flow.get('packet_count'),
        'byte_count': flow.get('byte_count'),
    })
    for section_name in ('http', 'tls', 'ssh', 'certificates', 'active_probes', 'fingerprints', 'enrichments'):
        for row in detail.get(section_name, []):
            item = {'record_type': section_name[:-1] if section_name.endswith('s') else section_name, 'flow_id': flow.get('id')}
            item.update(row)
            rows.append(item)
    return rows


def _all_flow_summary_rows(conn) -> list[dict[str, Any]]:
    sql = """
        SELECT
            f.id AS flow_id,
            s.filename,
            s.sha256,
            f.protocol,
            f.transport,
            f.src_ip,
            f.src_port,
            f.dst_ip,
            f.dst_port,
            f.packet_count,
            f.byte_count,
            f.selection_label,
            (
                SELECT oh.host
                FROM observations_http oh
                WHERE oh.flow_id = f.id AND oh.host IS NOT NULL AND oh.host != ''
                ORDER BY oh.observed_at, oh.id
                LIMIT 1
            ) AS http_host,
            (
                SELECT ot.sni
                FROM observations_tls ot
                WHERE ot.flow_id = f.id AND ot.sni IS NOT NULL AND ot.sni != ''
                ORDER BY ot.observed_at, ot.id
                LIMIT 1
            ) AS tls_sni,
            (
                SELECT fp.fingerprint_value
                FROM fingerprints fp
                WHERE fp.flow_id = f.id AND fp.fingerprint_type = 'ja4' AND fp.provenance = 'pcap_derived'
                ORDER BY fp.id
                LIMIT 1
            ) AS observed_ja4,
            (
                SELECT fp.fingerprint_value
                FROM fingerprints fp
                WHERE fp.flow_id = f.id AND fp.fingerprint_type = 'ja3s' AND fp.provenance = 'pcap_derived'
                ORDER BY fp.id
                LIMIT 1
            ) AS observed_ja3s,
            (
                SELECT fp.fingerprint_value
                FROM fingerprints fp
                WHERE fp.flow_id = f.id AND fp.fingerprint_type = 'jarm'
                ORDER BY fp.id DESC
                LIMIT 1
            ) AS any_jarm,
            (
                SELECT cert.subject_dn
                FROM certificates cert
                WHERE cert.flow_id = f.id
                ORDER BY cert.chain_position, cert.id
                LIMIT 1
            ) AS cert_subject
        FROM flows f
        JOIN samples s ON s.id = f.sample_id
        ORDER BY f.id
    """
    return [dict(row) for row in conn.execute(sql).fetchall()]


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    normalized_rows = rows or [{}]
    fieldnames: list[str] = []
    for row in normalized_rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in normalized_rows:
            writer.writerow({key: _jsonish(value) for key, value in row.items()})


def _jsonish(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)
