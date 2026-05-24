from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def extract_and_store_certificates(conn, pcap_path: Path, flow: dict[str, Any]) -> dict[str, Any]:
    display_filter = f"({_flow_display_filter(flow)}) && tls.handshake.certificate"
    cmd = [
        'tshark', '-r', str(pcap_path), '-Y', display_filter,
        '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=f',
        '-e', 'frame.time_epoch',
        '-e', 'tls.handshake.certificate',
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return {
            'inserted': 0,
            'warnings': [f"Certificate extraction tshark step failed for flow {flow.get('id')}: {proc.stderr.strip() or 'unknown tshark error'}"],
            'decode_failures': 0,
            'parse_failures': 0,
        }

    inserted = 0
    decode_failures = 0
    parse_failures = 0
    seen_leafs: set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        observed_at, cert_hex_blob = parts[:2]
        if not cert_hex_blob.strip():
            continue
        cert_hex_values = [v.strip() for v in cert_hex_blob.split(',') if v.strip()]
        chain_position = 0
        for cert_hex in cert_hex_values:
            cert_bytes = _decode_tshark_hex(cert_hex)
            if not cert_bytes:
                decode_failures += 1
                continue
            try:
                cert = x509.load_der_x509_certificate(cert_bytes)
            except Exception:
                parse_failures += 1
                continue

            leaf_sha256 = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            if chain_position == 0 and leaf_sha256 in seen_leafs:
                continue
            if chain_position == 0:
                seen_leafs.add(leaf_sha256)

            spki_sha256 = hashlib.sha256(
                cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()
            san_values = []
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_values = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                san_values = []

            issuer_dn = cert.issuer.rfc4514_string() if cert.issuer else None
            subject_dn = cert.subject.rfc4514_string() if cert.subject else None
            is_self_signed = int(bool(issuer_dn and subject_dn and issuer_dn == subject_dn))

            conn.execute(
                """
                INSERT INTO certificates (
                    flow_id, leaf_sha256, spki_sha256, serial_number,
                    subject_dn, issuer_dn, san_json, not_before, not_after,
                    is_self_signed, chain_position, pem_text, provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow['id'],
                    leaf_sha256,
                    spki_sha256,
                    format(cert.serial_number, 'x'),
                    subject_dn,
                    issuer_dn,
                    json.dumps(san_values) if san_values else None,
                    cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else None,
                    cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else None,
                    is_self_signed,
                    chain_position,
                    cert.public_bytes(serialization.Encoding.PEM).decode('utf-8', errors='ignore'),
                    'pcap_observed',
                ),
            )
            inserted += 1
            chain_position += 1
    warnings = []
    if decode_failures or parse_failures:
        warnings.append(
            f"Certificate extraction skipped some certificate blobs for flow {flow.get('id')} (decode_failures={decode_failures}, parse_failures={parse_failures})."
        )
    return {
        'inserted': inserted,
        'warnings': warnings,
        'decode_failures': decode_failures,
        'parse_failures': parse_failures,
    }


def _decode_tshark_hex(value: str) -> bytes:
    cleaned = value.replace(':', '').replace(' ', '').replace('\n', '').replace('\r', '')
    if not cleaned:
        return b''
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b''


def _flow_display_filter(flow: dict[str, Any]) -> str:
    transport = (flow.get('transport') or 'TCP').lower()
    src_ip = flow['src_ip']
    dst_ip = flow['dst_ip']
    src_port = flow['src_port'] or 0
    dst_port = flow['dst_port'] or 0
    return (
        f"((ip.src=={src_ip} && {transport}.srcport=={src_port} && ip.dst=={dst_ip} && {transport}.dstport=={dst_port})"
        f" || (ip.src=={dst_ip} && {transport}.srcport=={dst_port} && ip.dst=={src_ip} && {transport}.dstport=={src_port}))"
    )
