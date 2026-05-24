from __future__ import annotations

import json
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import Any

from werkzeug.utils import secure_filename

from .file_identity import sha256_file
from .certificate_service import extract_and_store_certificates


class PcapParseError(RuntimeError):
    pass


def ingest_pcap(
    conn,
    source_path: Path,
    original_filename: str,
    upload_dir: Path,
    mode: str = "passive",
) -> dict[str, Any]:
    file_sha256 = sha256_file(source_path)
    existing_sample = conn.execute(
        "SELECT * FROM samples WHERE sha256 = ?",
        (file_sha256,),
    ).fetchone()
    if existing_sample:
        _refresh_sample_selection_labels(conn, existing_sample['id'])
        flows = conn.execute(
            "SELECT * FROM flows WHERE sample_id = ? ORDER BY id",
            (existing_sample["id"],),
        ).fetchall()
        return {
            "deduplicated": True,
            "sha256": file_sha256,
            "sample": dict(existing_sample),
            "flows": [dict(row) for row in flows],
            "parse_warnings": [],
        }

    stored_path = _store_uploaded_pcap(source_path, original_filename, file_sha256, upload_dir)
    file_size = stored_path.stat().st_size
    flow_records = parse_flows_with_tshark(stored_path)

    run_cur = conn.execute(
        """
        INSERT INTO runs (mode, status, input_type, input_name, input_sha256, parse_summary_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            mode,
            "parsed",
            "pcap_upload",
            original_filename,
            file_sha256,
            json.dumps({"flow_count": len(flow_records)}),
        ),
    )
    run_id = run_cur.lastrowid

    protocol_summary = _protocol_summary(flow_records)
    sample_cur = conn.execute(
        """
        INSERT INTO samples (
            run_id,
            filename,
            sha256,
            filesize_bytes,
            capture_start_ts,
            capture_end_ts,
            packet_count,
            conversation_count,
            protocol_summary_json,
            source_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            original_filename,
            file_sha256,
            file_size,
            _min_value(flow_records, "start_ts"),
            _max_value(flow_records, "end_ts"),
            sum(record["packet_count"] for record in flow_records),
            len(flow_records),
            json.dumps(protocol_summary),
            "uploaded_pcap",
        ),
    )
    sample_id = sample_cur.lastrowid

    stored_flows: list[dict[str, Any]] = []
    for record in flow_records:
        selection_label = build_selection_label(record)
        summary_json = json.dumps(
            {
                "protocols_seen": record["protocols_seen"],
                "packet_count": record["packet_count"],
                "byte_count": record["byte_count"],
            }
        )
        cur = conn.execute(
            """
            INSERT INTO flows (
                sample_id,
                flow_key,
                protocol,
                transport,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                start_ts,
                end_ts,
                packet_count,
                byte_count,
                client_to_server_packets,
                server_to_client_packets,
                selection_label,
                summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_id,
                record["flow_key"],
                record["protocol"],
                record["transport"],
                record["src_ip"],
                record["src_port"],
                record["dst_ip"],
                record["dst_port"],
                record["start_ts"],
                record["end_ts"],
                record["packet_count"],
                record["byte_count"],
                record["client_to_server_packets"],
                record["server_to_client_packets"],
                selection_label,
                summary_json,
            ),
        )
        stored = dict(record)
        stored["id"] = cur.lastrowid
        stored["sample_id"] = sample_id
        stored["selection_label"] = selection_label
        stored_flows.append(stored)

    parse_warnings: list[str] = []
    for flow in stored_flows:
        parse_warnings.extend(_extract_and_store_observations(conn, stored_path, sample_id, flow))

    _refresh_sample_selection_labels(conn, sample_id)
    sample = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    flows = conn.execute("SELECT * FROM flows WHERE sample_id = ? ORDER BY id", (sample_id,)).fetchall()
    return {
        "deduplicated": False,
        "sha256": file_sha256,
        "sample": dict(sample),
        "flows": [dict(row) for row in flows],
        "parse_warnings": parse_warnings,
    }


def parse_flows_with_tshark(pcap_path: Path) -> list[dict[str, Any]]:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "frame.protocols",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return parse_flows_with_scapy(pcap_path)
    if proc.returncode != 0:
        raise PcapParseError(proc.stderr.strip() or "tshark flow parsing failed")

    flows: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 10:
            continue
        time_epoch, frame_len, src_ip, dst_ip, tcp_s, tcp_d, udp_s, udp_d, proto_col, proto_stack = parts[:10]
        if not src_ip or not dst_ip:
            continue
        transport = "TCP" if tcp_s or tcp_d else "UDP" if udp_s or udp_d else "IP"
        src_port = _int_or_none(tcp_s or udp_s)
        dst_port = _int_or_none(tcp_d or udp_d)
        if src_port is None and dst_port is None and transport == "IP":
            continue

        endpoints = sorted([
            (src_ip, src_port or 0),
            (dst_ip, dst_port or 0),
        ])
        flow_key = f"{transport}|{endpoints[0][0]}:{endpoints[0][1]}|{endpoints[1][0]}:{endpoints[1][1]}"
        ts = _float_or_none(time_epoch)
        flen = _int_or_zero(frame_len)
        protocol = _choose_protocol(proto_col or transport or "UNKNOWN", src_port, dst_port)

        if flow_key not in flows:
            flows[flow_key] = {
                "flow_key": flow_key,
                "transport": transport,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "start_ts": ts,
                "end_ts": ts,
                "packet_count": 0,
                "byte_count": 0,
                "client_to_server_packets": 0,
                "server_to_client_packets": 0,
                "protocols_seen": [],
            }

        record = flows[flow_key]
        record["packet_count"] += 1
        record["byte_count"] += flen
        record["end_ts"] = ts if ts is not None else record["end_ts"]
        if proto_col and proto_col not in record["protocols_seen"]:
            record["protocols_seen"].append(proto_col)
        if src_ip == record["src_ip"] and src_port == record["src_port"]:
            record["client_to_server_packets"] += 1
        else:
            record["server_to_client_packets"] += 1

    return list(flows.values())


def parse_flows_with_scapy(pcap_path: Path) -> list[dict[str, Any]]:
    try:
        from scapy.all import IP, IPv6, PcapReader, TCP, UDP
    except ModuleNotFoundError as exc:
        raise PcapParseError("Neither tshark nor Scapy is available for PCAP parsing") from exc

    flows: OrderedDict[str, dict[str, Any]] = OrderedDict()
    try:
        reader = PcapReader(str(pcap_path))
    except Exception as exc:
        raise PcapParseError(f"Unable to open PCAP with Scapy fallback: {exc}") from exc

    with reader:
        for pkt in reader:
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            src_ip = getattr(ip_layer, 'src', None)
            dst_ip = getattr(ip_layer, 'dst', None)
            if not src_ip or not dst_ip:
                continue

            if pkt.haslayer(TCP):
                l4 = pkt.getlayer(TCP)
                transport = 'TCP'
                src_port = int(l4.sport)
                dst_port = int(l4.dport)
            elif pkt.haslayer(UDP):
                l4 = pkt.getlayer(UDP)
                transport = 'UDP'
                src_port = int(l4.sport)
                dst_port = int(l4.dport)
            else:
                continue

            endpoints = sorted([
                (src_ip, src_port),
                (dst_ip, dst_port),
            ])
            flow_key = f"{transport}|{endpoints[0][0]}:{endpoints[0][1]}|{endpoints[1][0]}:{endpoints[1][1]}"
            ts = float(pkt.time) if getattr(pkt, 'time', None) is not None else None
            proto_guess = _choose_protocol(transport, src_port, dst_port)

            if flow_key not in flows:
                flows[flow_key] = {
                    'flow_key': flow_key,
                    'transport': transport,
                    'protocol': proto_guess,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'start_ts': ts,
                    'end_ts': ts,
                    'packet_count': 0,
                    'byte_count': 0,
                    'client_to_server_packets': 0,
                    'server_to_client_packets': 0,
                    'protocols_seen': [proto_guess],
                }

            record = flows[flow_key]
            record['packet_count'] += 1
            record['byte_count'] += len(pkt)
            record['end_ts'] = ts if ts is not None else record['end_ts']
            if src_ip == record['src_ip'] and src_port == record['src_port']:
                record['client_to_server_packets'] += 1
            else:
                record['server_to_client_packets'] += 1

    return list(flows.values())


def build_selection_label(flow: dict[str, Any]) -> str:
    return (
        f"{flow['protocol']} | {flow['src_ip']}:{flow['src_port'] or 0} -> "
        f"{flow['dst_ip']}:{flow['dst_port'] or 0} | {flow['packet_count']} pkts"
    )


def _refresh_sample_selection_labels(conn, sample_id: int) -> None:
    flows = conn.execute('SELECT * FROM flows WHERE sample_id = ? ORDER BY id', (sample_id,)).fetchall()
    for flow in flows:
        label = _build_enriched_selection_label(conn, dict(flow))
        conn.execute('UPDATE flows SET selection_label = ? WHERE id = ?', (label, flow['id']))


def _build_enriched_selection_label(conn, flow: dict[str, Any]) -> str:
    base = build_selection_label(flow)
    hints: list[str] = []

    if (flow.get('protocol') or '').upper() == 'TLS':
        tls_row = conn.execute(
            "SELECT sni, tls_version_negotiated FROM observations_tls WHERE flow_id = ? AND (sni IS NOT NULL OR tls_version_negotiated IS NOT NULL) ORDER BY observed_at, id LIMIT 1",
            (flow['id'],),
        ).fetchone()
        if tls_row:
            if tls_row.get('sni'):
                hints.append(f"SNI={tls_row['sni']}")
            if tls_row.get('tls_version_negotiated'):
                hints.append(f"TLS={tls_row['tls_version_negotiated']}")
        fp_row = conn.execute(
            "SELECT fingerprint_type, fingerprint_value, provenance FROM fingerprints WHERE flow_id = ? ORDER BY CASE WHEN provenance = 'pcap_derived' THEN 0 ELSE 1 END, id LIMIT 3",
            (flow['id'],),
        ).fetchall()
        for row in fp_row:
            fp_type = row.get('fingerprint_type')
            fp_value = row.get('fingerprint_value')
            if fp_type in {'ja4', 'jarm', 'ja3s'} and fp_value:
                hints.append(f"{fp_type.upper()}={_short_hint(fp_value)}")
                break

    if (flow.get('protocol') or '').upper() == 'HTTP':
        http_row = conn.execute(
            "SELECT host, full_url FROM observations_http WHERE flow_id = ? AND (host IS NOT NULL OR full_url IS NOT NULL) ORDER BY observed_at, id LIMIT 1",
            (flow['id'],),
        ).fetchone()
        if http_row:
            if http_row.get('host'):
                hints.append(f"Host={http_row['host']}")
            elif http_row.get('full_url'):
                hints.append(f"URL={_short_hint(http_row['full_url'], max_len=32)}")

    if not hints:
        return base
    return f"{base} | {' | '.join(hints[:2])}"


def _short_hint(value: str, max_len: int = 22) -> str:
    if len(value) <= max_len:
        return value
    return f"{value[:max_len]}…"


def _extract_and_store_observations(conn, pcap_path: Path, sample_id: int, flow: dict[str, Any]) -> list[str]:
    if shutil.which("tshark") is None:
        return ["tshark is unavailable, so protocol-specific extraction was skipped."]
    warnings: list[str] = []
    _extract_http_observations(conn, pcap_path, flow)
    _extract_tls_observations_and_fingerprints(conn, pcap_path, sample_id, flow)
    cert_result = extract_and_store_certificates(conn, pcap_path, flow)
    warnings.extend(cert_result.get('warnings', []))
    return warnings


def _extract_http_observations(conn, pcap_path: Path, flow: dict[str, Any]) -> None:
    display_filter = f"({_flow_display_filter(flow)}) && http"
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.request.full_uri",
        "-e", "http.user_agent",
        "-e", "http.response.code",
        "-e", "http.location",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return

    inserted = False
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        observed_at, method, host, uri, full_uri, user_agent, status_code, location = parts[:8]
        if not any([method, host, uri, full_uri, user_agent, status_code, location]):
            continue
        conn.execute(
            """
            INSERT INTO observations_http (
                flow_id, request_method, host, uri, full_url, user_agent,
                status_code, location_header, observed_at, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow["id"],
                method or None,
                host or None,
                uri or None,
                full_uri or None,
                user_agent or None,
                _int_or_none(status_code),
                location or None,
                observed_at or None,
                "pcap_observed",
            ),
        )
        inserted = True
    if inserted:
        conn.execute(
            "UPDATE flows SET protocol = ? WHERE id = ? AND protocol NOT IN ('TLS','SSH')",
            ("HTTP", flow["id"]),
        )


def _extract_tls_observations_and_fingerprints(conn, pcap_path: Path, sample_id: int, flow: dict[str, Any]) -> None:
    display_filter = f"({_flow_display_filter(flow)}) && tls"
    cmd = [
        "tshark", "-r", str(pcap_path), "-Y", display_filter,
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.extensions_alpn_str",
        "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.ja3_full",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.ja3s_full",
        "-e", "tls.handshake.ja4",
        "-e", "tls.handshake.ja4_r",
        "-e", "tls.handshake.ciphersuite",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return

    fingerprint_seen: set[tuple[str, str]] = set()
    inserted = False
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 12:
            continue
        (
            observed_at,
            handshake_type,
            version,
            sni,
            alpn,
            ja3,
            ja3_full,
            ja3s,
            ja3s_full,
            ja4,
            ja4_r,
            selected_cipher,
        ) = parts[:12]
        if not any([handshake_type, version, sni, alpn, ja3, ja3s, ja4, selected_cipher]):
            continue

        tls_role = _tls_role_from_handshake_type(handshake_type)
        cur = conn.execute(
            """
            INSERT INTO observations_tls (
                flow_id, tls_role, tls_version_offered, tls_version_negotiated,
                sni, alpn_json, selected_cipher, observed_at, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow["id"],
                tls_role,
                version or None,
                version or None,
                sni or None,
                json.dumps([alpn]) if alpn else None,
                selected_cipher or None,
                observed_at or None,
                "pcap_observed",
            ),
        )
        tls_obs_id = cur.lastrowid
        inserted = True

        for fp_type, fp_value, full_text, role in (
            ("ja3", ja3, ja3_full, "client"),
            ("ja3s", ja3s, ja3s_full, "server"),
            ("ja4", ja4, ja4_r, "client"),
        ):
            value = (fp_value or "").strip()
            if not value:
                continue
            key = (fp_type, value)
            if key in fingerprint_seen:
                continue
            fingerprint_seen.add(key)
            conn.execute(
                """
                INSERT INTO fingerprints (
                    flow_id, sample_id, fingerprint_type, fingerprint_value,
                    role, source_observation_table, source_observation_id,
                    component_summary_json, display_summary_json, observed_at, provenance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow["id"],
                    sample_id,
                    fp_type,
                    value,
                    role,
                    "observations_tls",
                    tls_obs_id,
                    json.dumps({"raw": full_text}) if full_text else None,
                    json.dumps({"label": value, "raw": full_text}) if full_text else json.dumps({"label": value}),
                    observed_at or None,
                    "pcap_derived",
                ),
            )

    if inserted:
        conn.execute("UPDATE flows SET protocol = ? WHERE id = ?", ("TLS", flow["id"]))


def _flow_display_filter(flow: dict[str, Any]) -> str:
    transport = (flow.get("transport") or "TCP").lower()
    src_ip = flow["src_ip"]
    dst_ip = flow["dst_ip"]
    src_port = flow["src_port"] or 0
    dst_port = flow["dst_port"] or 0
    return (
        f"((ip.src=={src_ip} && {transport}.srcport=={src_port} && ip.dst=={dst_ip} && {transport}.dstport=={dst_port})"
        f" || (ip.src=={dst_ip} && {transport}.srcport=={dst_port} && ip.dst=={src_ip} && {transport}.dstport=={src_port}))"
    )


def _tls_role_from_handshake_type(value: str | None) -> str | None:
    mapping = {
        "1": "client_hello",
        "2": "server_hello",
        "11": "certificate",
    }
    return mapping.get((value or "").strip(), "session") if value else None


def _store_uploaded_pcap(source_path: Path, original_filename: str, file_sha256: str, upload_dir: Path) -> Path:
    upload_dir.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(original_filename) or "upload.pcap"
    suffix = Path(safe_name).suffix or ".pcap"
    target = upload_dir / f"{file_sha256}{suffix}"
    if not target.exists():
        shutil.copy2(source_path, target)
    return target


def _protocol_summary(flow_records: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for record in flow_records:
        summary[record["protocol"]] = summary.get(record["protocol"], 0) + 1
    return summary


def _min_value(records: list[dict[str, Any]], key: str):
    values = [record[key] for record in records if record.get(key) is not None]
    return min(values) if values else None


def _max_value(records: list[dict[str, Any]], key: str):
    values = [record[key] for record in records if record.get(key) is not None]
    return max(values) if values else None


def _float_or_none(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def _int_or_zero(value: str | None) -> int:
    try:
        return int(value) if value else 0
    except ValueError:
        return 0


def _choose_protocol(proto_label: str, src_port: int | None, dst_port: int | None) -> str:
    ports = {src_port or 0, dst_port or 0}
    normalized = (proto_label or "").upper()
    if 443 in ports or "TLS" in normalized:
        return "TLS"
    if 80 in ports or "HTTP" in normalized:
        return "HTTP"
    if 22 in ports or "SSH" in normalized:
        return "SSH"
    return normalized or "UNKNOWN"
