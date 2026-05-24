from __future__ import annotations

import json
from typing import Any

from .reference_service import search_reference_fingerprints


def get_flow_detail(conn, flow_id: int) -> dict[str, Any] | None:
    flow = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
    if not flow:
        return None

    http_rows = conn.execute(
        "SELECT * FROM observations_http WHERE flow_id = ? ORDER BY observed_at, id",
        (flow_id,),
    ).fetchall()
    tls_rows = conn.execute(
        "SELECT * FROM observations_tls WHERE flow_id = ? ORDER BY observed_at, id",
        (flow_id,),
    ).fetchall()
    ssh_rows = conn.execute(
        "SELECT * FROM observations_ssh WHERE flow_id = ? ORDER BY observed_at, id",
        (flow_id,),
    ).fetchall()
    cert_rows = conn.execute(
        "SELECT * FROM certificates WHERE flow_id = ? ORDER BY chain_position, id",
        (flow_id,),
    ).fetchall()
    active_probe_rows = conn.execute(
        "SELECT * FROM active_probes WHERE flow_id = ? ORDER BY id DESC",
        (flow_id,),
    ).fetchall()
    fingerprint_rows = conn.execute(
        "SELECT * FROM fingerprints WHERE flow_id = ? ORDER BY fingerprint_type, provenance, id",
        (flow_id,),
    ).fetchall()
    sample_row = conn.execute(
        "SELECT run_id FROM samples WHERE id = ?",
        (flow['sample_id'],),
    ).fetchone()

    fingerprints = [dict(row) for row in fingerprint_rows]
    reference_matches = {}
    shodan_queries = {}
    for fp in fingerprints:
        fp_key = f"{fp['fingerprint_type']}:{fp['fingerprint_value']}"
        reference_matches[fp_key] = search_reference_fingerprints(
            conn,
            fingerprint_value=fp['fingerprint_value'],
            fingerprint_type=fp['fingerprint_type'],
            limit=5,
        )
        query = build_shodan_query(fp['fingerprint_type'], fp['fingerprint_value'])
        if query:
            shodan_queries[fp_key] = query

    comparison_summary = build_fingerprint_comparison_summary(fingerprints)
    http_comparison = build_http_comparison_summary([dict(row) for row in http_rows])
    enrichments = []
    if sample_row:
        target_values = {
            flow.get('src_ip'),
            flow.get('dst_ip'),
            *[row.get('sni') for row in map(dict, tls_rows)],
            *[fp.get('fingerprint_value') for fp in fingerprints],
        }
        target_values = {value for value in target_values if value}
        if target_values:
            placeholders = ','.join('?' for _ in target_values)
            sql = f"""
                SELECT * FROM enrichments
                WHERE run_id = ? AND target_value IN ({placeholders})
                ORDER BY id DESC
            """
            enrichments = [
                dict(row) for row in conn.execute(sql, [sample_row['run_id'], *sorted(target_values)]).fetchall()
            ]

    return {
        "flow": dict(flow),
        "http": [dict(row) for row in http_rows],
        "tls": [dict(row) for row in tls_rows],
        "ssh": [dict(row) for row in ssh_rows],
        "certificates": [dict(row) for row in cert_rows],
        "active_probes": [dict(row) for row in active_probe_rows],
        "fingerprints": fingerprints,
        "reference_matches": reference_matches,
        "shodan_queries": shodan_queries,
        "enrichments": enrichments,
        "comparison_summary": comparison_summary,
        "http_comparison": http_comparison,
    }


def build_fingerprint_comparison_summary(fingerprints: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for fp in fingerprints:
        bucket = summary.setdefault(fp['fingerprint_type'], {
            'local_values': [],
            'external_values': [],
            'state': 'no_comparison_data',
        })
        value = fp.get('fingerprint_value')
        if not value:
            continue
        if (fp.get('provenance') or '').startswith('pcap_') or fp.get('provenance') == 'light_active_probe':
            if value not in bucket['local_values']:
                bucket['local_values'].append(value)
        if fp.get('provenance') == 'third_party_enrichment':
            if value not in bucket['external_values']:
                bucket['external_values'].append(value)

    for bucket in summary.values():
        local_values = set(bucket['local_values'])
        external_values = set(bucket['external_values'])
        if local_values and external_values:
            bucket['state'] = 'match' if local_values & external_values else 'mismatch'
        elif external_values and not local_values:
            bucket['state'] = 'awaiting_local_or_active_value'
        elif local_values and not external_values:
            bucket['state'] = 'awaiting_external_value'
    return summary


def build_shodan_query(fingerprint_type: str, fingerprint_value: str) -> str | None:
    mapping = {
        'ja3s': 'ssl.ja3s',
        'jarm': 'ssl.jarm',
        'hassh': 'ssh.hassh',
    }
    shodan_filter = mapping.get((fingerprint_type or '').lower())
    if not shodan_filter or not fingerprint_value:
        return None
    return f"{shodan_filter}:{fingerprint_value}"


def build_http_comparison_summary(http_rows: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = {
        'passive': [row for row in http_rows if row.get('provenance') in {'pcap_observed', 'pcap_derived'}],
        'light': [row for row in http_rows if row.get('provenance') == 'light_active_probe'],
        'mimic': [row for row in http_rows if row.get('provenance') == 'pcap_mimic_active'],
    }
    passive = _merge_http_rows(buckets['passive'])
    light = _merge_http_rows(buckets['light'])
    mimic = _merge_http_rows(buckets['mimic'])
    return {
        'passive': _http_row_snapshot(passive),
        'light': _http_row_snapshot(light),
        'mimic': _http_row_snapshot(mimic),
        'light_vs_passive': _compare_http_rows(passive, light),
        'mimic_vs_passive': _compare_http_rows(passive, mimic),
    }


def _http_row_snapshot(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    response_body = _safe_json(row.get('response_body_summary_json'))
    response_headers = _safe_json(row.get('response_headers_json'))
    return {
        'id': row.get('id'),
        'provenance': row.get('provenance'),
        'method': row.get('request_method'),
        'host': row.get('host'),
        'uri': row.get('uri'),
        'full_url': row.get('full_url'),
        'query_string': row.get('query_string'),
        'status_code': row.get('status_code'),
        'location_header': row.get('location_header'),
        'user_agent': row.get('user_agent'),
        'content_type': response_headers.get('content-type') or response_headers.get('Content-Type'),
        'body_preview_utf8': response_body.get('body_preview_utf8'),
        'body_size_captured': response_body.get('body_size_captured'),
        'observed_at': row.get('observed_at'),
    }


def _compare_http_rows(baseline: dict[str, Any] | None, candidate: dict[str, Any] | None) -> dict[str, Any]:
    if not baseline and not candidate:
        return {'state': 'no_data', 'changed_fields': [], 'same_fields': [], 'notes': 'no passive or active HTTP data'}
    if baseline and not candidate:
        return {'state': 'awaiting_candidate', 'changed_fields': [], 'same_fields': [], 'notes': 'passive HTTP exists but no active comparison row yet'}
    if candidate and not baseline:
        return {'state': 'no_passive_baseline', 'changed_fields': [], 'same_fields': [], 'notes': 'active HTTP row exists but no passive HTTP baseline exists'}

    fields = ['method', 'host', 'uri', 'full_url', 'status_code', 'content_type', 'location_header', 'user_agent']
    changed_fields = []
    same_fields = []
    for field in fields:
        left = _http_row_snapshot(baseline).get(field)
        right = _http_row_snapshot(candidate).get(field)
        if _normalize_http_value(left) == _normalize_http_value(right):
            if left or right:
                same_fields.append(field)
        else:
            changed_fields.append({
                'field': field,
                'passive': left,
                'candidate': right,
            })
    return {
        'state': 'match' if not changed_fields else 'changed',
        'changed_fields': changed_fields,
        'same_fields': same_fields,
        'notes': 'active HTTP shape matches passive baseline' if not changed_fields else 'active HTTP shape differs from passive baseline',
    }


def _normalize_http_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip()
    return value


def _safe_json(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        loaded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _merge_http_rows(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    merged = dict(rows[0])
    request_headers: dict[str, Any] = {}
    response_headers: dict[str, Any] = {}
    body_summary: dict[str, Any] = {}
    for row in rows:
        for field in (
            'request_method',
            'host',
            'uri',
            'full_url',
            'query_string',
            'user_agent',
            'referer',
            'status_code',
            'location_header',
            'observed_at',
        ):
            if not merged.get(field) and row.get(field):
                merged[field] = row.get(field)
        request_headers.update(_safe_json(row.get('request_headers_json')))
        response_headers.update(_safe_json(row.get('response_headers_json')))
        body_summary.update(_safe_json(row.get('response_body_summary_json')))
    merged['request_headers_json'] = json.dumps(request_headers) if request_headers else None
    merged['response_headers_json'] = json.dumps(response_headers) if response_headers else None
    merged['response_body_summary_json'] = json.dumps(body_summary) if body_summary else None
    return merged
