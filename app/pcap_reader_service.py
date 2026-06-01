from __future__ import annotations

import json
import ipaddress
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scapy.all import ARP, Dot3, Ether, IP, IPv6, PcapReader, Raw, TCP, UDP
from werkzeug.utils import secure_filename

from ja4plus.processor import Processor
from ja4plus.utils.ssh_utils import extract_hassh, parse_ssh_packet

from .artifact_analysis_service import breakdown_for_artifact, role_for_artifact_type
from .config import Config
from .file_identity import sha256_file
from .match_service import hydrate_artifact_matches, store_artifact_matches
from .zeek_service import run_zeek_capture


class PcapParseError(RuntimeError):
    pass


_MANUF_TABLE_CACHE: list[tuple[str, str]] | None = None


def ingest_pcap(
    conn,
    source_path: Path,
    original_filename: str,
    upload_dir: Path,
    zeek_output_root: Path,
    zeek_script_path: Path,
) -> dict[str, Any]:
    file_sha256 = sha256_file(source_path)
    existing = conn.execute("SELECT id FROM samples WHERE sha256 = ?", (file_sha256,)).fetchone()
    if existing:
        sample_id = int(existing["id"])
        _refresh_sample_packet_endpoints(conn, sample_id, upload_dir)
        return {
            "deduplicated": True,
            "sample": get_sample_overview(conn, sample_id),
            "packets": list_packet_rows(conn, sample_id),
        }

    stored_path = _store_uploaded_pcap(source_path, original_filename, file_sha256, upload_dir)
    packet_rows, artifact_rows, capture_bounds = _analyze_packets(stored_path)
    zeek_summary = run_zeek_capture(stored_path, zeek_output_root, zeek_script_path)

    run_cur = conn.execute(
        """
        INSERT INTO runs (mode, status, input_type, input_name, input_sha256, parse_summary_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "passive",
            "parsed",
            "pcap_upload",
            original_filename,
            file_sha256,
            json.dumps(
                {
                    "packet_count": len(packet_rows),
                    "artifact_count": len(artifact_rows),
                    "artifact_types": sorted({row["artifact_type"] for row in artifact_rows}),
                }
            ),
        ),
    )

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
            zeek_summary_json,
            parse_summary_json,
            source_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_cur.lastrowid,
            original_filename,
            file_sha256,
            stored_path.stat().st_size,
            capture_bounds["start_ts_text"],
            capture_bounds["end_ts_text"],
            len(packet_rows),
            json.dumps(zeek_summary),
            json.dumps(
                {
                    "artifact_count": len(artifact_rows),
                    "artifact_types": sorted({row["artifact_type"] for row in artifact_rows}),
                    "zeek_status": zeek_summary["status"],
                }
            ),
            "uploaded_pcap",
        ),
    )
    sample_id = sample_cur.lastrowid

    packet_id_map: dict[int, int] = {}
    for packet in packet_rows:
        cur = conn.execute(
            """
            INSERT INTO packet_rows (
                sample_id,
                packet_number,
                ts_epoch,
                ts_text,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                transport,
                protocol,
                length_bytes,
                endpoint_text,
                artifact_summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_id,
                packet["packet_number"],
                packet["ts_epoch"],
                packet["ts_text"],
                packet["src_ip"],
                packet["src_port"],
                packet["dst_ip"],
                packet["dst_port"],
                packet["transport"],
                packet["protocol"],
                packet["length_bytes"],
                packet["endpoint_text"],
                json.dumps(packet["artifact_summary"]),
            ),
        )
        packet_id_map[packet["packet_number"]] = cur.lastrowid

    for artifact in artifact_rows:
        packet_id = packet_id_map[artifact["packet_number"]]
        cur = conn.execute(
            """
            INSERT INTO packet_artifacts (
                sample_id,
                packet_id,
                artifact_type,
                artifact_value,
                role,
                raw_fingerprint,
                raw_original_order,
                parts_json,
                provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_id,
                packet_id,
                artifact["artifact_type"],
                artifact["artifact_value"],
                artifact["role"],
                artifact["raw_fingerprint"],
                artifact["raw_original_order"],
                json.dumps(artifact["parts"]),
                artifact["provenance"],
            ),
        )
        store_artifact_matches(conn, cur.lastrowid, artifact["artifact_type"], artifact["artifact_value"])

    _refresh_sample_packet_endpoints(conn, sample_id, upload_dir)

    return {
        "deduplicated": False,
        "sample": get_sample_overview(conn, sample_id),
        "packets": list_packet_rows(conn, sample_id),
    }


def get_sample_overview(conn, sample_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if not row:
        return None
    sample = dict(row)
    sample["zeek_summary"] = _loads(sample.get("zeek_summary_json"), {})
    sample["parse_summary"] = _loads(sample.get("parse_summary_json"), {})
    return sample


def list_packet_rows(conn, sample_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM packet_rows
        WHERE sample_id = ?
        ORDER BY packet_number
        """,
        (sample_id,),
    ).fetchall()
    packets = []
    for row in rows:
        packet = dict(row)
        packet["artifact_summary"] = _loads(packet.get("artifact_summary_json"), [])
        packets.append(packet)
    return packets


def get_packet_detail(conn, packet_id: int) -> dict[str, Any] | None:
    packet = conn.execute("SELECT * FROM packet_rows WHERE id = ?", (packet_id,)).fetchone()
    if not packet:
        return None

    packet_dict = dict(packet)
    packet_dict["artifact_summary"] = _loads(packet_dict.get("artifact_summary_json"), [])
    sample = get_sample_overview(conn, int(packet_dict["sample_id"]))
    packet_inspector = _build_packet_inspector(sample, int(packet_dict["packet_number"]))
    if packet_inspector:
        packet_dict["packet_inspector"] = packet_inspector

    artifact_rows = conn.execute(
        """
        SELECT *
        FROM packet_artifacts
        WHERE packet_id = ?
        ORDER BY artifact_type, id
        """,
        (packet_id,),
    ).fetchall()
    artifacts = []
    for row in artifact_rows:
        artifact = dict(row)
        artifact["parts"] = _loads(artifact.get("parts_json"), {})
        artifact["matches"] = hydrate_artifact_matches(conn, int(artifact["id"]))
        artifacts.append(artifact)

    return {
        "packet": packet_dict,
        "artifacts": artifacts,
        "sample": sample,
    }


def _build_packet_inspector(sample: dict[str, Any] | None, packet_number: int) -> dict[str, Any] | None:
    if not sample:
        return None
    stored_path = _find_stored_pcap(
        Config.UPLOAD_DIR,
        str(sample.get("sha256") or ""),
        str(sample.get("filename") or ""),
    )
    if stored_path is None or not stored_path.exists():
        return None

    packet = _read_packet_by_number(stored_path, packet_number)
    if packet is None:
        return None

    verbose_text = _extract_tshark_packet_verbose(stored_path, packet_number)
    http_host = _match_verbose_value(verbose_text, r"^\s*Host:\s+(.+)$")
    user_agent = _match_verbose_value(verbose_text, r"^\s*User-Agent:\s+(.+)$")
    tls_sni = _match_verbose_value(verbose_text, r"^\s*Server Name:\s+(.+)$")
    certificate_authority = _match_verbose_value(verbose_text, r"^\s*Issuer:\s+(.+)$")
    certificate_subject = _match_verbose_value(verbose_text, r"^\s*Subject:\s+(.+)$")
    certificate_serial = _match_verbose_value(verbose_text, r"^\s*Serial Number:\s+(.+)$")
    destination_domain = _normalize_domain_label(http_host) or _normalize_domain_label(tls_sni)
    src_mac, dst_mac = _get_link_layer_addresses(packet)

    return {
        "destination_domain": destination_domain,
        "http_host": _normalize_domain_label(http_host),
        "user_agent": user_agent,
        "tls_sni": _normalize_domain_label(tls_sni),
        "certificate_authority": certificate_authority,
        "certificate_subject": certificate_subject,
        "certificate_serial": certificate_serial,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_mac_display": _format_mac_display(src_mac),
        "dst_mac_display": _format_mac_display(dst_mac),
        "layers": _build_packet_layer_tree(packet),
        "hexdump": _build_hex_rows(bytes(packet)),
    }


def _refresh_sample_packet_endpoints(conn, sample_id: int, upload_dir: Path) -> None:
    sample = conn.execute("SELECT filename, sha256 FROM samples WHERE id = ?", (sample_id,)).fetchone()
    if not sample:
        return
    stored_path = _find_stored_pcap(upload_dir, str(sample["sha256"] or ""), str(sample["filename"] or ""))
    if stored_path is None or not stored_path.exists():
        return

    domain_map = _extract_tshark_packet_domains(stored_path)

    rows = conn.execute(
        """
        SELECT id, packet_number
        FROM packet_rows
        WHERE sample_id = ?
        ORDER BY packet_number
        """,
        (sample_id,),
    ).fetchall()
    row_id_by_packet_number = {int(row["packet_number"]): int(row["id"]) for row in rows}

    try:
        packet_iter = _iter_capture_packets(stored_path)
        for packet_number, packet in enumerate(packet_iter, start=1):
            row_id = row_id_by_packet_number.get(packet_number)
            if row_id is None:
                continue
            src_ip, dst_ip = _get_ips(packet)
            src_port, dst_port = _get_ports(packet)
            src_mac, dst_mac = _get_link_layer_addresses(packet)
            endpoint_text = _format_packet_endpoints(src_ip, src_port, dst_ip, dst_port, src_mac, dst_mac)
            domain = domain_map.get(packet_number)
            if domain and _is_public_ip(dst_ip) and _normalize_domain_label(domain) != dst_ip:
                endpoint_text = _decorate_destination_endpoint(src_ip, src_port, dst_ip, dst_port, domain)
            conn.execute(
                "UPDATE packet_rows SET endpoint_text = ? WHERE id = ?",
                (endpoint_text, row_id),
            )
    except PcapParseError:
        return


def _analyze_packets(pcap_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str | None]]:
    processor = Processor()
    ja3_map = _extract_tshark_tls_hashes(pcap_path)
    domain_map = _extract_tshark_packet_domains(pcap_path)

    packet_rows: list[dict[str, Any]] = []
    artifact_rows: list[dict[str, Any]] = []
    capture_start: float | None = None
    capture_end: float | None = None

    seen_hassh: set[tuple[int, str, str]] = set()

    for packet_number, packet in enumerate(_iter_capture_packets(pcap_path), start=1):
        ts_epoch = _float_time(getattr(packet, "time", None))
        capture_start = ts_epoch if capture_start is None else min(capture_start, ts_epoch or capture_start)
        capture_end = ts_epoch if capture_end is None else max(capture_end, ts_epoch or capture_end)

        row = _build_packet_row(packet_number, packet, ts_epoch)
        row["endpoint_text"] = _decorate_destination_endpoint(
            row["src_ip"],
            row["src_port"],
            row["dst_ip"],
            row["dst_port"],
            domain_map.get(packet_number),
        )
        packet_artifacts = _extract_packet_artifacts(packet, packet_number, processor)

        if packet_number in ja3_map:
            hashes = ja3_map[packet_number]
            if hashes.get("ja3"):
                packet_artifacts.append(_artifact_stub(packet_number, "ja3", hashes["ja3"], "client"))
            if hashes.get("ja3s"):
                packet_artifacts.append(_artifact_stub(packet_number, "ja3s", hashes["ja3s"], "server"))

        hassh_entries = _extract_hassh_artifacts(packet, packet_number, seen_hassh)
        packet_artifacts.extend(hassh_entries)

        row["artifact_summary"] = [
            {
                "artifact_type": artifact["artifact_type"],
                "artifact_value": artifact["artifact_value"],
                "role": artifact["role"],
            }
            for artifact in packet_artifacts
        ]
        packet_rows.append(row)
        artifact_rows.extend(packet_artifacts)

    return packet_rows, artifact_rows, {
        "start_ts_text": _format_epoch(capture_start),
        "end_ts_text": _format_epoch(capture_end),
    }


def _extract_packet_artifacts(packet, packet_number: int, processor: Processor) -> list[dict[str, Any]]:
    artifacts = []
    for result in processor.process_packet(packet):
        artifact_type = result["type"]
        artifact_value = result["fingerprint"]
        if artifact_type == "ja4l" and artifact_value.startswith("JA4L-S="):
            artifact_type = "ja4ls"
        artifacts.append(
            {
                "packet_number": packet_number,
                "artifact_type": artifact_type,
                "artifact_value": artifact_value,
                "role": _role_for_artifact_type(artifact_type),
                "raw_fingerprint": result.get("raw"),
                "raw_original_order": result.get("raw_original_order"),
                "parts": breakdown_for_artifact(artifact_type, artifact_value),
                "provenance": "pcap_derived",
            }
        )
    return artifacts


def _extract_hassh_artifacts(packet, packet_number: int, seen_hassh: set[tuple[int, str, str]]) -> list[dict[str, Any]]:
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return []
    payload = bytes(packet[Raw])
    info = parse_ssh_packet(payload)
    if not info or info.get("type") != "kexinit":
        return []
    fingerprint = extract_hassh(payload)
    if not fingerprint:
        return []

    role = "client"
    if int(packet[TCP].sport) == 22:
        role = "server"
    elif int(packet[TCP].dport) == 22:
        role = "client"
    elif int(packet[TCP].sport) < int(packet[TCP].dport):
        role = "server"

    artifact_type = "hassh_server" if role == "server" else "hassh"
    dedupe_key = (packet_number, artifact_type, fingerprint)
    if dedupe_key in seen_hassh:
        return []
    seen_hassh.add(dedupe_key)
    return [
        {
            "packet_number": packet_number,
            "artifact_type": artifact_type,
            "artifact_value": fingerprint,
            "role": role,
            "raw_fingerprint": None,
            "raw_original_order": None,
            "parts": {
                "label": "SSH key exchange hash",
                "kex_algorithms": info.get("kex_algorithms", ""),
                "encryption_algorithms": info.get("encryption_algorithms", ""),
                "mac_algorithms": info.get("mac_algorithms", ""),
                "compression_algorithms": info.get("compression_algorithms", ""),
            },
            "provenance": "pcap_derived",
        }
    ]


def _extract_tshark_tls_hashes(pcap_path: Path) -> dict[int, dict[str, str]]:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "tls.handshake.ja3",
        "-e",
        "tls.handshake.ja3s",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {}
    if proc.returncode != 0:
        return {}

    result: dict[int, dict[str, str]] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if not parts:
            continue
        try:
            packet_number = int(parts[0])
        except ValueError:
            continue
        result[packet_number] = {
            "ja3": parts[1].strip() if len(parts) > 1 else "",
            "ja3s": parts[2].strip() if len(parts) > 2 else "",
        }
    return result


def _extract_tshark_packet_domains(pcap_path: Path) -> dict[int, str]:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "http.host",
        "-e",
        "tls.handshake.extensions_server_name",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {}
    if proc.returncode != 0:
        return {}

    result: dict[int, str] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if not parts:
            continue
        try:
            packet_number = int(parts[0])
        except ValueError:
            continue
        http_host = parts[1].strip() if len(parts) > 1 else ""
        tls_sni = parts[2].strip() if len(parts) > 2 else ""
        domain = _normalize_domain_label(http_host) or _normalize_domain_label(tls_sni)
        if domain:
            result[packet_number] = domain
    return result


def _extract_tshark_packet_verbose(pcap_path: Path, packet_number: int) -> str:
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        f"frame.number == {packet_number}",
        "-V",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout or ""


def _build_packet_row(packet_number: int, packet, ts_epoch: float | None) -> dict[str, Any]:
    src_ip, dst_ip = _get_ips(packet)
    src_port, dst_port = _get_ports(packet)
    transport = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
    protocol = _infer_protocol(packet)
    src_mac, dst_mac = _get_link_layer_addresses(packet)
    endpoint_text = _format_packet_endpoints(src_ip, src_port, dst_ip, dst_port, src_mac, dst_mac)
    return {
        "packet_number": packet_number,
        "ts_epoch": ts_epoch,
        "ts_text": _format_epoch(ts_epoch),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "transport": transport,
        "protocol": protocol,
        "length_bytes": len(bytes(packet)),
        "endpoint_text": endpoint_text,
    }


def _read_packet_by_number(pcap_path: Path, packet_number: int):
    try:
        packet_iter = _iter_capture_packets(pcap_path)
        for current_number, packet in enumerate(packet_iter, start=1):
            if current_number == packet_number:
                return packet
    except PcapParseError:
        return None
    return None


def _iter_capture_packets(capture_path: Path):
    """Yield packets from pcap or pcapng, converting with editcap only if Scapy cannot open it directly."""
    converted_path: Path | None = None
    try:
        try:
            reader = PcapReader(str(capture_path))
        except Exception as direct_exc:
            converted_path = _convert_capture_to_pcap(capture_path, direct_exc)
            try:
                reader = PcapReader(str(converted_path))
            except Exception as converted_exc:
                raise PcapParseError(
                    "Unable to read capture as PCAP/PCAPNG after editcap conversion: "
                    f"{converted_exc}"
                ) from converted_exc

        with reader:
            yield from reader
    finally:
        if converted_path is not None:
            converted_path.unlink(missing_ok=True)


def _convert_capture_to_pcap(capture_path: Path, direct_exc: Exception) -> Path:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        converted_path = Path(tmp.name)

    cmd = ["editcap", "-F", "pcap", str(capture_path), str(converted_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
        converted_path.unlink(missing_ok=True)
        raise PcapParseError(
            f"Unable to read capture directly ({direct_exc}); editcap is not installed for PCAPNG conversion"
        ) from exc
    except Exception as exc:
        converted_path.unlink(missing_ok=True)
        raise PcapParseError(f"Unable to read capture directly ({direct_exc}); editcap conversion failed: {exc}") from exc

    if proc.returncode != 0:
        converted_path.unlink(missing_ok=True)
        stderr_tail = (proc.stderr or "").strip()[-500:]
        raise PcapParseError(
            f"Unable to read capture directly ({direct_exc}); editcap conversion failed: {stderr_tail or 'no stderr'}"
        )

    return converted_path


def _match_verbose_value(text: str, pattern: str) -> str:
    if not text:
        return ""
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        return ""
    value = str(match.group(1)).strip()
    return value.replace("\\r", "").replace("\\n", "").strip()


def _build_packet_layer_tree(packet) -> list[dict[str, Any]]:
    layers: list[dict[str, Any]] = []
    current = packet
    while current is not None:
        layer_name = getattr(current, "name", None) or current.__class__.__name__
        field_rows = []
        for key, value in getattr(current, "fields", {}).items():
            field_rows.append(
                {
                    "name": str(key),
                    "value": _stringify_field_value(value),
                }
            )
        layers.append(
            {
                "name": str(layer_name),
                "field_count": len(field_rows),
                "fields": field_rows,
            }
        )
        payload = getattr(current, "payload", None)
        if payload is None or payload.__class__.__name__ == "NoPayload":
            break
        current = payload
    return layers


def _stringify_field_value(value: Any) -> str:
    if isinstance(value, bytes):
        if not value:
            return ""
        if len(value) > 32:
            return f"{value[:32].hex()}... ({len(value)} bytes)"
        return value.hex()
    if isinstance(value, (list, tuple, set)):
        rendered = [_stringify_field_value(item) for item in value]
        if len(rendered) > 8:
            return ", ".join(rendered[:8]) + f", ... ({len(rendered)} items)"
        return ", ".join(rendered)
    return str(value)


def _build_hex_rows(packet_bytes: bytes, width: int = 16) -> list[dict[str, str]]:
    rows = []
    for offset in range(0, len(packet_bytes), width):
        chunk = packet_bytes[offset:offset + width]
        rows.append(
            {
                "offset": f"{offset:04x}",
                "hex": " ".join(f"{byte:02x}" for byte in chunk),
                "ascii": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk),
            }
        )
    return rows


def _decorate_destination_endpoint(src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None, domain: str | None) -> str:
    src = _format_endpoint(src_ip, src_port)
    dst = _format_endpoint(dst_ip, dst_port)
    normalized_domain = _normalize_domain_label(domain)
    if normalized_domain and _is_public_ip(dst_ip) and normalized_domain != dst_ip:
        dst = f"{dst} ({normalized_domain})"
    return f"{src} -> {dst}"


def _artifact_stub(packet_number: int, artifact_type: str, artifact_value: str, role: str) -> dict[str, Any]:
    return {
        "packet_number": packet_number,
        "artifact_type": artifact_type,
        "artifact_value": artifact_value,
        "role": role,
        "raw_fingerprint": None,
        "raw_original_order": None,
        "parts": breakdown_for_artifact(artifact_type, artifact_value),
        "provenance": "pcap_derived",
    }


def _role_for_artifact_type(artifact_type: str) -> str:
    return role_for_artifact_type(artifact_type)


def _normalize_domain_label(value: str | None) -> str:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate:
        return ""
    if "," in candidate:
        candidate = candidate.split(",", 1)[0].strip()
    return candidate


def _format_mac_display(mac: str) -> str:
    normalized = str(mac or "").strip()
    if not normalized:
        return ""
    vendor = _lookup_mac_vendor(normalized)
    return f"{normalized} ({vendor})" if vendor else normalized


def _lookup_mac_vendor(mac: str) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
    if len(normalized) < 6:
        return ""
    table = _load_manuf_table()
    for prefix, vendor in table:
        if normalized.startswith(prefix):
            return vendor
    return ""


def _load_manuf_table() -> list[tuple[str, str]]:
    global _MANUF_TABLE_CACHE
    if _MANUF_TABLE_CACHE is not None:
        return _MANUF_TABLE_CACHE

    entries: list[tuple[str, str]] = []
    try:
        proc = subprocess.run(
            ["tshark", "-G", "manuf"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        _MANUF_TABLE_CACHE = []
        return _MANUF_TABLE_CACHE

    if proc.returncode != 0:
        _MANUF_TABLE_CACHE = []
        return _MANUF_TABLE_CACHE

    for line in proc.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\t+", line.strip())
        if len(parts) < 2:
            continue
        prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
        vendor = str(parts[2] if len(parts) > 2 and parts[2] else parts[1]).strip()
        if len(prefix) >= 6 and vendor:
            entries.append((prefix, vendor))

    entries.sort(key=lambda item: len(item[0]), reverse=True)
    _MANUF_TABLE_CACHE = entries
    return _MANUF_TABLE_CACHE


def _is_public_ip(value: str | None) -> bool:
    try:
        ip_obj = ipaddress.ip_address(str(value or ""))
    except ValueError:
        return False
    if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_unspecified:
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        private_v4 = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return not any(ip_obj in network for network in private_v4)
    private_v6 = ipaddress.ip_network("fc00::/7")
    return ip_obj not in private_v6


def _infer_protocol(packet) -> str:
    if packet.haslayer(TCP):
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
        ports = {sport, dport}
        if 22 in ports:
            return "SSH"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        if 443 in ports:
            return "TLS"
        if 445 in ports:
            return "SMB"
        return "TCP"
    if packet.haslayer(UDP):
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
        ports = {sport, dport}
        if 443 in ports:
            return "QUIC"
        if 53 in ports:
            return "DNS"
        if 67 in ports or 68 in ports or 546 in ports or 547 in ports:
            return "DHCP"
        return "UDP"
    return packet.lastlayer().name if getattr(packet, "lastlayer", None) else "IP"


def _get_ips(packet) -> tuple[str, str]:
    if packet.haslayer(IP):
        return str(packet[IP].src), str(packet[IP].dst)
    if packet.haslayer(IPv6):
        return str(packet[IPv6].src), str(packet[IPv6].dst)
    return "", ""


def _get_ports(packet) -> tuple[int | None, int | None]:
    if packet.haslayer(TCP):
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if packet.haslayer(UDP):
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return None, None


def _get_link_layer_addresses(packet) -> tuple[str, str]:
    for layer_type in (Ether, Dot3):
        if packet.haslayer(layer_type):
            layer = packet[layer_type]
            return str(getattr(layer, "src", "") or "").strip(), str(getattr(layer, "dst", "") or "").strip()
    if packet.haslayer(ARP):
        layer = packet[ARP]
        return str(getattr(layer, "hwsrc", "") or "").strip(), str(getattr(layer, "hwdst", "") or "").strip()
    src = str(getattr(packet, "src", "") or "").strip()
    dst = str(getattr(packet, "dst", "") or "").strip()
    if (not src or not dst) and getattr(packet, "fields", None):
        src = src or str(packet.fields.get("src", "") or packet.fields.get("hwsrc", "") or "").strip()
        dst = dst or str(packet.fields.get("dst", "") or packet.fields.get("hwdst", "") or "").strip()
    return src, dst


def _format_endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if ip and port is not None else ip or "unknown"


def _format_packet_endpoints(
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    src_mac: str,
    dst_mac: str,
) -> str:
    if src_ip or dst_ip:
        return f"{_format_endpoint(src_ip, src_port)} -> {_format_endpoint(dst_ip, dst_port)}"
    src = src_mac or "unknown"
    dst = dst_mac or "unknown"
    return f"{src} -> {dst}"


def _format_epoch(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")


def _float_time(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _store_uploaded_pcap(source_path: Path, original_filename: str, sha256: str, upload_dir: Path) -> Path:
    upload_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(original_filename).suffix.lower() or ".pcap"
    safe_name = secure_filename(Path(original_filename).stem) or "capture"
    destination = upload_dir / f"{sha256}_{safe_name}{suffix}"
    if not destination.exists():
        shutil.copy2(source_path, destination)
    return destination


def _find_stored_pcap(upload_dir: Path, sha256: str, original_filename: str) -> Path | None:
    suffix = Path(original_filename).suffix.lower() or ".pcap"
    safe_name = secure_filename(Path(original_filename).stem) or "capture"
    candidates = [
        upload_dir / f"{sha256}_{safe_name}{suffix}",
        upload_dir / f"{sha256}.pcap",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    matches = sorted(upload_dir.glob(f"{sha256}_*"))
    if matches:
        return matches[0]
    return None
