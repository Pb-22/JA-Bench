from __future__ import annotations

import json
from typing import Any

from .flow_detail_service import build_shodan_query
from .shodan_service import ShodanNotConfiguredError, ShodanService


def enrich_flow_with_shodan(conn, shodan_service: ShodanService, flow_id: int, force_refresh: bool = False) -> dict[str, Any]:
    if not shodan_service.enabled:
        raise ShodanNotConfiguredError('Shodan API key is not configured')

    flow = conn.execute(
        """
        SELECT f.*, s.run_id, s.id AS sample_id
        FROM flows f
        JOIN samples s ON s.id = f.sample_id
        WHERE f.id = ?
        """,
        (flow_id,),
    ).fetchone()
    if not flow:
        raise ValueError('Flow not found for enrichment')

    fingerprints = conn.execute(
        "SELECT * FROM fingerprints WHERE flow_id = ? ORDER BY id",
        (flow_id,),
    ).fetchall()
    tls_rows = conn.execute(
        "SELECT * FROM observations_tls WHERE flow_id = ? ORDER BY observed_at, id",
        (flow_id,),
    ).fetchall()

    service_ip = _choose_service_ip(flow)
    host_result = shodan_service.host(service_ip, minify=False, force_refresh=force_refresh)
    host_value = host_result.value
    passive = _extract_passive_tls_material(host_value)

    host_enrichment_id = conn.execute(
        """
        INSERT INTO enrichments (run_id, target_type, target_value, provider, provider_query, result_summary_json, raw_result_json, observed_at, provenance)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        """,
        (
            flow['run_id'],
            'ip',
            service_ip,
            'shodan',
            f'host:{service_ip}',
            json.dumps({
                'from_cache': host_result.from_cache,
                'ports': host_value.get('ports'),
                'hostnames': host_value.get('hostnames'),
                'jarm': passive.get('jarm'),
                'ja3s': passive.get('ja3s'),
                'cert_subject': passive.get('cert_subject'),
            }),
            json.dumps(host_value),
            'third_party_enrichment',
        ),
    ).lastrowid

    inserted_external_fingerprints = []
    for fp_type, fp_value in (('jarm', passive.get('jarm')), ('ja3s', passive.get('ja3s'))):
        value = (fp_value or '').strip()
        if not value:
            continue
        exists = conn.execute(
            """
            SELECT id FROM fingerprints
            WHERE flow_id = ? AND sample_id = ? AND fingerprint_type = ? AND fingerprint_value = ? AND provenance = ?
            LIMIT 1
            """,
            (flow_id, flow['sample_id'], fp_type, value, 'third_party_enrichment'),
        ).fetchone()
        if exists:
            inserted_external_fingerprints.append({'fingerprint_type': fp_type, 'fingerprint_value': value, 'inserted': False})
            continue
        conn.execute(
            """
            INSERT INTO fingerprints (
                flow_id, sample_id, fingerprint_type, fingerprint_value,
                role, source_observation_table, source_observation_id,
                display_summary_json, observed_at, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (
                flow_id,
                flow['sample_id'],
                fp_type,
                value,
                'server',
                'enrichments',
                host_enrichment_id,
                json.dumps({'label': value, 'source': 'shodan_host_lookup'}),
                'third_party_enrichment',
            ),
        )
        inserted_external_fingerprints.append({'fingerprint_type': fp_type, 'fingerprint_value': value, 'inserted': True})

    fingerprint_counts = []
    for fp in fingerprints:
        query = build_shodan_query(fp['fingerprint_type'], fp['fingerprint_value'])
        if not query:
            continue
        count_result = shodan_service.count(query, force_refresh=force_refresh)
        result_count = _extract_shodan_total(count_result.value)
        external_row = conn.execute(
            """
            INSERT INTO external_prevalence_observations (
                fingerprint_id, provider, query_value, query_type, result_count,
                result_scope_note, raw_summary_json, observed_at, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (
                fp['id'],
                'shodan',
                query,
                fp['fingerprint_type'],
                result_count,
                'Shodan count result for candidate prevalence comparison',
                json.dumps({
                    'from_cache': count_result.from_cache,
                    'response': count_result.value,
                }),
                'third_party_enrichment',
            ),
        ).lastrowid
        conn.execute(
            """
            INSERT INTO enrichments (run_id, target_type, target_value, provider, provider_query, result_summary_json, raw_result_json, observed_at, provenance)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """,
            (
                flow['run_id'],
                'fingerprint',
                fp['fingerprint_value'],
                'shodan',
                query,
                json.dumps({'total': result_count, 'from_cache': count_result.from_cache}),
                json.dumps(count_result.value),
                'third_party_enrichment',
            ),
        )
        fingerprint_counts.append({
            'fingerprint_id': fp['id'],
            'fingerprint_type': fp['fingerprint_type'],
            'fingerprint_value': fp['fingerprint_value'],
            'query': query,
            'result_count': result_count,
            'external_prevalence_observation_id': external_row,
        })

    comparison = _build_comparison_summary(conn, flow_id)
    return {
        'flow_id': flow_id,
        'service_ip': service_ip,
        'host_lookup': {
            'from_cache': host_result.from_cache,
            'jarm': passive.get('jarm'),
            'ja3s': passive.get('ja3s'),
            'cert_subject': passive.get('cert_subject'),
            'hostnames': host_value.get('hostnames') or [],
            'ports': host_value.get('ports') or [],
        },
        'inserted_external_fingerprints': inserted_external_fingerprints,
        'fingerprint_counts': fingerprint_counts,
        'comparison': comparison,
    }


def _choose_service_ip(flow: dict[str, Any]) -> str:
    service_ports = {22, 80, 443, 8443}
    if (flow.get('dst_port') or 0) in service_ports:
        return flow['dst_ip']
    if (flow.get('src_port') or 0) in service_ports:
        return flow['src_ip']
    return flow['dst_ip']


def _extract_passive_tls_material(host_value: dict[str, Any]) -> dict[str, Any]:
    ssl_entries = []
    for banner in host_value.get('data', []) or []:
        ssl = banner.get('ssl')
        if isinstance(ssl, dict):
            ssl_entries.append(ssl)
    top_ssl = host_value.get('ssl')
    if isinstance(top_ssl, dict):
        ssl_entries.insert(0, top_ssl)

    jarm = None
    ja3s = None
    cert_subject = None
    for ssl in ssl_entries:
        if not jarm and ssl.get('jarm'):
            jarm = ssl.get('jarm')
        if not ja3s and ssl.get('ja3s'):
            ja3s = ssl.get('ja3s')
        cert = ssl.get('cert') or {}
        if not cert_subject:
            cert_subject = (
                cert.get('subject', {}).get('CN')
                or cert.get('subject', {}).get('commonName')
                or cert.get('subject', {}).get('cn')
            )
        if jarm and ja3s and cert_subject:
            break
    return {
        'jarm': jarm,
        'ja3s': ja3s,
        'cert_subject': cert_subject,
    }


def _extract_shodan_total(payload: dict[str, Any]) -> int | None:
    total = payload.get('total')
    try:
        return int(total) if total is not None else None
    except (TypeError, ValueError):
        return None


def _build_comparison_summary(conn, flow_id: int) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT fingerprint_type, fingerprint_value, provenance FROM fingerprints WHERE flow_id = ? ORDER BY id",
        (flow_id,),
    ).fetchall()
    grouped: dict[str, dict[str, list[str]]] = {}
    for row in rows:
        grouped.setdefault(row['fingerprint_type'], {}).setdefault(row['provenance'], []).append(row['fingerprint_value'])

    summary: dict[str, Any] = {}
    for fp_type, by_provenance in grouped.items():
        local_values = sorted({v for prov, vals in by_provenance.items() if prov.startswith('pcap_') or prov == 'light_active_probe' for v in vals})
        external_values = sorted({v for prov, vals in by_provenance.items() if prov == 'third_party_enrichment' for v in vals})
        state = 'no_comparison_data'
        if local_values and external_values:
            state = 'match' if set(local_values) & set(external_values) else 'mismatch'
        elif external_values and not local_values:
            state = 'awaiting_local_or_active_value'
        elif local_values and not external_values:
            state = 'awaiting_external_value'
        summary[fp_type] = {
            'local_values': local_values,
            'external_values': external_values,
            'state': state,
        }
    return summary
