from __future__ import annotations

import json
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def run_light_jarm_probe(conn, vendor_root: Path, flow_id: int, force_refresh: bool = False) -> dict[str, Any]:
    flow, context = _get_flow_context(conn, flow_id)
    target_host, target_port = _choose_probe_target(flow)
    existing_fp = conn.execute(
        """
        SELECT * FROM fingerprints
        WHERE flow_id = ?
          AND fingerprint_type = 'jarm'
          AND provenance = 'light_active_probe'
        ORDER BY id DESC
        LIMIT 1
        """,
        (flow_id,),
    ).fetchone()
    if existing_fp and not force_refresh:
        return {
            'flow_id': flow_id,
            'target_host': target_host,
            'target_port': target_port,
            'fingerprint_value': existing_fp['fingerprint_value'],
            'from_cache': True,
        }

    script_path = vendor_root / 'jarm' / 'jarm.py'
    if not script_path.exists():
        raise RuntimeError(f'JARM script not found at {script_path}')

    cmd = ['python3', str(script_path), target_host, '-p', str(target_port), '-j']
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or 'JARM probe failed')

    payload = _parse_jarm_output(proc.stdout)
    jarm_value = (payload.get('result') or '').strip()
    if not jarm_value:
        raise RuntimeError('JARM probe returned no result')

    active_probe_id = _insert_active_probe(
        conn,
        run_id=flow['run_id'],
        flow_id=flow_id,
        probe_type='jarm',
        target_host=target_host,
        target_port=target_port,
        request_summary={'command': cmd},
        response_summary=payload,
        status='completed',
        provenance='light_active_probe',
    )

    existing_same = conn.execute(
        """
        SELECT id FROM fingerprints
        WHERE flow_id = ? AND sample_id = ? AND fingerprint_type = 'jarm'
          AND fingerprint_value = ? AND provenance = 'light_active_probe'
        LIMIT 1
        """,
        (flow_id, flow['sample_id'], jarm_value),
    ).fetchone()
    inserted = False
    if not existing_same:
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
                'jarm',
                jarm_value,
                'server',
                'active_probes',
                active_probe_id,
                json.dumps({'label': jarm_value, 'source': 'light_jarm_probe'}),
                'light_active_probe',
            ),
        )
        inserted = True

    return {
        'flow_id': flow_id,
        'target_host': target_host,
        'target_port': target_port,
        'fingerprint_value': jarm_value,
        'active_probe_id': active_probe_id,
        'inserted_fingerprint': inserted,
        'from_cache': False,
        'raw': payload,
    }


def run_light_tls_cert_grab(conn, flow_id: int, force_refresh: bool = False) -> dict[str, Any]:
    flow, context = _get_flow_context(conn, flow_id)
    target_host, target_port = _choose_probe_target(flow)
    existing = conn.execute(
        "SELECT * FROM certificates WHERE flow_id = ? AND provenance = 'light_active_probe' ORDER BY id DESC LIMIT 1",
        (flow_id,),
    ).fetchone()
    if existing and not force_refresh:
        return {
            'flow_id': flow_id,
            'target_host': target_host,
            'target_port': target_port,
            'subject_dn': existing['subject_dn'],
            'issuer_dn': existing['issuer_dn'],
            'from_cache': True,
        }

    server_name = context.get('sni') or target_host
    payload = _grab_tls_certificate(target_host, target_port, server_name=server_name)
    cert = payload['certificate']

    active_probe_id = _insert_active_probe(
        conn,
        run_id=flow['run_id'],
        flow_id=flow_id,
        probe_type='tls_cert_grab',
        target_host=target_host,
        target_port=target_port,
        request_summary={'server_name': server_name},
        response_summary=payload,
        status='completed',
        provenance='light_active_probe',
    )

    exists_same = conn.execute(
        "SELECT id FROM certificates WHERE flow_id = ? AND leaf_sha256 = ? AND provenance = 'light_active_probe' LIMIT 1",
        (flow_id, cert['leaf_sha256']),
    ).fetchone()
    inserted = False
    if not exists_same:
        conn.execute(
            """
            INSERT INTO certificates (
                flow_id, tls_observation_id, leaf_sha256, spki_sha256, serial_number,
                subject_dn, issuer_dn, san_json, not_before, not_after,
                is_self_signed, chain_position, pem_text, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow_id,
                None,
                cert['leaf_sha256'],
                cert['spki_sha256'],
                cert['serial_number'],
                cert['subject_dn'],
                cert['issuer_dn'],
                json.dumps(cert['san_dns_names']) if cert['san_dns_names'] else None,
                cert['not_before'],
                cert['not_after'],
                cert['is_self_signed'],
                0,
                cert['pem_text'],
                'light_active_probe',
            ),
        )
        inserted = True

    return {
        'flow_id': flow_id,
        'target_host': target_host,
        'target_port': target_port,
        'active_probe_id': active_probe_id,
        'inserted_certificate': inserted,
        'from_cache': False,
        'certificate': cert,
    }


def run_light_http_metadata_probe(conn, flow_id: int, force_refresh: bool = False) -> dict[str, Any]:
    flow, context = _get_flow_context(conn, flow_id)
    target_url, request_summary = _build_http_probe_request(flow, context)
    existing = conn.execute(
        "SELECT * FROM active_probes WHERE flow_id = ? AND probe_type = 'http_metadata' AND provenance = 'light_active_probe' ORDER BY id DESC LIMIT 1",
        (flow_id,),
    ).fetchone()
    if existing and not force_refresh:
        return {
            'flow_id': flow_id,
            'target_url': target_url,
            'from_cache': True,
            'response_summary': json.loads(existing['response_summary_json']) if existing['response_summary_json'] else {},
        }

    payload = _run_curl_metadata_probe(target_url, request_summary['user_agent'])
    active_probe_id = _insert_active_probe(
        conn,
        run_id=flow['run_id'],
        flow_id=flow_id,
        probe_type='http_metadata',
        target_host=request_summary['host'],
        target_port=request_summary['port'],
        request_summary=request_summary,
        response_summary=payload,
        status='completed',
        provenance='light_active_probe',
    )
    _insert_http_probe_observation(
        conn,
        flow_id=flow_id,
        request_summary=request_summary,
        response_summary=payload,
        provenance='light_active_probe',
    )
    return {
        'flow_id': flow_id,
        'target_url': target_url,
        'active_probe_id': active_probe_id,
        'from_cache': False,
        'response_summary': payload,
    }


def run_pcap_mimic_request(conn, flow_id: int, force_refresh: bool = False) -> dict[str, Any]:
    flow, context = _get_flow_context(conn, flow_id)
    target_url, request_summary = _build_http_probe_request(flow, context, pcap_mimic=True)
    existing = conn.execute(
        "SELECT * FROM active_probes WHERE flow_id = ? AND probe_type = 'pcap_mimic_request' AND provenance = 'pcap_mimic_active' ORDER BY id DESC LIMIT 1",
        (flow_id,),
    ).fetchone()
    if existing and not force_refresh:
        return {
            'flow_id': flow_id,
            'target_url': target_url,
            'from_cache': True,
            'response_summary': json.loads(existing['response_summary_json']) if existing['response_summary_json'] else {},
        }

    payload = _run_curl_metadata_probe(
        target_url,
        request_summary['user_agent'],
        method=request_summary['method'],
        follow_redirects=False,
        byte_cap=2048,
    )
    active_probe_id = _insert_active_probe(
        conn,
        run_id=flow['run_id'],
        flow_id=flow_id,
        probe_type='pcap_mimic_request',
        target_host=request_summary['host'],
        target_port=request_summary['port'],
        request_summary=request_summary,
        response_summary=payload,
        status='completed',
        provenance='pcap_mimic_active',
    )
    _insert_http_probe_observation(
        conn,
        flow_id=flow_id,
        request_summary=request_summary,
        response_summary=payload,
        provenance='pcap_mimic_active',
    )
    return {
        'flow_id': flow_id,
        'target_url': target_url,
        'active_probe_id': active_probe_id,
        'from_cache': False,
        'response_summary': payload,
    }


def _get_flow_context(conn, flow_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
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
        raise ValueError('Flow not found for light testing')
    http_row = conn.execute(
        """
        SELECT * FROM observations_http
        WHERE flow_id = ?
          AND provenance IN ('pcap_observed', 'pcap_derived')
        ORDER BY
            CASE WHEN provenance = 'pcap_observed' THEN 0 ELSE 1 END,
            observed_at,
            id
        LIMIT 1
        """,
        (flow_id,),
    ).fetchone()
    tls_row = conn.execute(
        """
        SELECT * FROM observations_tls
        WHERE flow_id = ?
          AND provenance IN ('pcap_observed', 'pcap_derived')
        ORDER BY
            CASE WHEN provenance = 'pcap_observed' THEN 0 ELSE 1 END,
            observed_at,
            id
        LIMIT 1
        """,
        (flow_id,),
    ).fetchone()
    return flow, {
        'http': dict(http_row) if http_row else {},
        'tls': dict(tls_row) if tls_row else {},
        'sni': tls_row.get('sni') if tls_row else None,
    }


def _choose_probe_target(flow: dict[str, Any]) -> tuple[str, int]:
    service_ports = {22, 80, 443, 8080, 8443}
    if (flow.get('dst_port') or 0) in service_ports:
        return flow['dst_ip'], int(flow['dst_port'])
    if (flow.get('src_port') or 0) in service_ports:
        return flow['src_ip'], int(flow['src_port'])
    return flow['dst_ip'], int(flow.get('dst_port') or 443)


def _build_http_probe_request(flow: dict[str, Any], context: dict[str, Any], pcap_mimic: bool = False) -> tuple[str, dict[str, Any]]:
    http = context.get('http') or {}
    tls = context.get('tls') or {}
    host = http.get('host') or tls.get('sni') or flow['dst_ip']
    port = int(flow.get('dst_port') or 443)
    scheme = 'https' if port in {443, 8443} or (flow.get('protocol') or '').upper() == 'TLS' else 'http'
    if http.get('full_url'):
        parsed = urlparse(http['full_url'])
        target_url = http['full_url']
        if not parsed.scheme:
            target_url = f"{scheme}://{host}{http.get('uri') or '/'}"
    else:
        path = http.get('uri') or '/'
        target_url = f"{scheme}://{host}{path}"
    observed_method = (http.get('request_method') or 'GET').upper()
    method = observed_method if observed_method in {'GET', 'HEAD'} else 'GET'
    if not pcap_mimic:
        method = 'HEAD' if scheme == 'https' else 'GET'
    user_agent = http.get('user_agent') or 'JA-Bench/0.1 LightTesting'
    return target_url, {
        'host': host,
        'port': port,
        'scheme': scheme,
        'url': target_url,
        'method': method,
        'observed_method': observed_method,
        'user_agent': user_agent,
        'follow_redirects': False,
        'byte_cap': 2048 if pcap_mimic else 1024,
    }


def _run_curl_metadata_probe(url: str, user_agent: str, method: str = 'HEAD', follow_redirects: bool = False, byte_cap: int = 1024) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(delete=False) as headers_file, tempfile.NamedTemporaryFile(delete=False) as body_file:
        headers_path = headers_file.name
        body_path = body_file.name
    cmd = [
        'curl', '--silent', '--show-error', '--insecure', '--max-time', '20', '--connect-timeout', '8',
        '--dump-header', headers_path, '--output', body_path, '--user-agent', user_agent,
        '--range', f'0-{max(0, byte_cap - 1)}', '--request', method,
    ]
    if not follow_redirects:
        cmd.extend(['--max-redirs', '0'])
    else:
        cmd.append('--location')
    cmd.append(url)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    headers_text = Path(headers_path).read_text(encoding='utf-8', errors='ignore') if Path(headers_path).exists() else ''
    body_bytes = Path(body_path).read_bytes() if Path(body_path).exists() else b''
    status_line = next((line for line in headers_text.splitlines() if line.startswith('HTTP/')), '')
    location = None
    content_type = None
    response_headers: dict[str, str] = {}
    for line in headers_text.splitlines():
        if ':' not in line:
            continue
        lower = line.lower()
        if lower.startswith('location:'):
            location = line.split(':', 1)[1].strip()
        if lower.startswith('content-type:'):
            content_type = line.split(':', 1)[1].strip()
        header_name, header_value = line.split(':', 1)
        response_headers[header_name.strip()] = header_value.strip()
    return {
        'curl_exit_code': proc.returncode,
        'status_line': status_line,
        'location': location,
        'content_type': content_type,
        'response_headers': response_headers,
        'body_preview_utf8': body_bytes[:byte_cap].decode('utf-8', errors='replace'),
        'body_size_captured': len(body_bytes[:byte_cap]),
        'stderr': proc.stderr.strip(),
        'stdout': proc.stdout.strip(),
    }


def _insert_http_probe_observation(conn, flow_id: int, request_summary: dict[str, Any], response_summary: dict[str, Any], provenance: str) -> None:
    parsed = urlparse(request_summary.get('url') or '')
    status_code = _status_code_from_line(response_summary.get('status_line'))
    conn.execute(
        """
        INSERT INTO observations_http (
            flow_id, request_method, host, uri, full_url, query_string,
            user_agent, referer, status_code, location_header,
            request_headers_json, response_headers_json,
            request_body_summary_json, response_body_summary_json,
            observed_at, provenance
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        """,
        (
            flow_id,
            request_summary.get('method'),
            request_summary.get('host') or parsed.hostname,
            parsed.path or '/',
            request_summary.get('url'),
            parsed.query or None,
            request_summary.get('user_agent'),
            None,
            status_code,
            response_summary.get('location'),
            json.dumps({
                'user-agent': request_summary.get('user_agent'),
                'method': request_summary.get('method'),
                'follow_redirects': request_summary.get('follow_redirects'),
                'byte_cap': request_summary.get('byte_cap'),
            }),
            json.dumps(response_summary.get('response_headers') or {}),
            None,
            json.dumps({
                'body_size_captured': response_summary.get('body_size_captured'),
                'body_preview_utf8': response_summary.get('body_preview_utf8'),
                'curl_exit_code': response_summary.get('curl_exit_code'),
                'status_line': response_summary.get('status_line'),
            }),
            provenance,
        ),
    )


def _status_code_from_line(status_line: str | None) -> int | None:
    if not status_line:
        return None
    parts = status_line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _grab_tls_certificate(host: str, port: int, server_name: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError('TLS cert grab returned no certificate')
    cert = x509.load_der_x509_certificate(der)
    leaf_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    spki_sha256 = hashes.Hash(hashes.SHA256())
    spki_sha256.update(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    san_values = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_values = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_values = []
    issuer_dn = cert.issuer.rfc4514_string() if cert.issuer else None
    subject_dn = cert.subject.rfc4514_string() if cert.subject else None
    return {
        'target_host': host,
        'server_name': server_name,
        'certificate': {
            'leaf_sha256': leaf_sha256,
            'spki_sha256': spki_sha256.finalize().hex(),
            'serial_number': format(cert.serial_number, 'x'),
            'subject_dn': subject_dn,
            'issuer_dn': issuer_dn,
            'san_dns_names': san_values,
            'not_before': cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else None,
            'not_after': cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else None,
            'is_self_signed': int(bool(issuer_dn and subject_dn and issuer_dn == subject_dn)),
            'pem_text': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8', errors='ignore'),
        },
    }


def _insert_active_probe(conn, run_id: int, flow_id: int, probe_type: str, target_host: str, target_port: int, request_summary: dict[str, Any], response_summary: dict[str, Any], status: str, provenance: str) -> int:
    return conn.execute(
        """
        INSERT INTO active_probes (
            run_id, flow_id, probe_type, target_host, target_port,
            request_summary_json, response_summary_json, status,
            started_at, completed_at, provenance
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
        """,
        (
            run_id,
            flow_id,
            probe_type,
            target_host,
            target_port,
            json.dumps(request_summary),
            json.dumps(response_summary),
            status,
            provenance,
        ),
    ).lastrowid


def _parse_jarm_output(stdout: str) -> dict[str, Any]:
    line = ''
    for candidate in stdout.splitlines():
        candidate = candidate.strip()
        if candidate:
            line = candidate
            break
    if not line:
        raise RuntimeError('JARM output was empty')
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'Unable to parse JARM output: {line}') from exc
    if not isinstance(payload, dict):
        raise RuntimeError('Unexpected JARM output type')
    return payload
