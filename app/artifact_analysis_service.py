from __future__ import annotations

from typing import Any


def breakdown_for_artifact(artifact_type: str, artifact_value: str) -> dict[str, Any]:
    normalized_type = str(artifact_type or "").strip().lower()
    value = str(artifact_value or "").strip()
    if normalized_type == "ja4":
        parts = value.split("_")
        base = parts[0] if parts else ""
        return {
            "ja4_a": base,
            "protocol": base[:1],
            "tls_version": base[1:3],
            "sni_flag": base[3:4],
            "cipher_count": base[4:6],
            "extension_count": base[6:8],
            "alpn": base[8:10],
            "ja4_b": parts[1] if len(parts) > 1 else "",
            "ja4_c": parts[2] if len(parts) > 2 else "",
        }
    if normalized_type == "ja4s":
        parts = value.split("_")
        base = parts[0] if parts else ""
        return {
            "ja4s_a": base,
            "protocol": base[:1],
            "tls_version": base[1:3],
            "extension_count": base[3:5],
            "alpn": base[5:7],
            "ja4s_b": parts[1] if len(parts) > 1 else "",
            "ja4s_c": parts[2] if len(parts) > 2 else "",
        }
    if normalized_type == "ja4h":
        parts = value.split("_")
        base = parts[0] if parts else ""
        return {
            "ja4h_a": base,
            "method": base[:2],
            "http_version": base[2:4],
            "cookie_flag": base[4:5],
            "referer_flag": base[5:6],
            "header_count": base[6:8],
            "accept_language": base[8:12],
            "ja4h_b": parts[1] if len(parts) > 1 else "",
            "ja4h_c": parts[2] if len(parts) > 2 else "",
            "ja4h_d": parts[3] if len(parts) > 3 else "",
        }
    if normalized_type in {"ja4t", "ja4ts"}:
        parts = value.split("_")
        labels = ("window_size", "tcp_options", "mss", "window_scale")
        return {labels[index]: part for index, part in enumerate(parts[:4])}
    if normalized_type == "ja4x":
        parts = value.split("_")
        return {
            "ja4x_a": parts[0] if len(parts) > 0 else "",
            "ja4x_b": parts[1] if len(parts) > 1 else "",
            "ja4x_c": parts[2] if len(parts) > 2 else "",
        }
    if normalized_type in {"ja4l", "ja4ls"}:
        _, _, rhs = value.partition("=")
        parts = rhs.split("_") if rhs else []
        return {
            "direction": "client" if normalized_type == "ja4l" else "server",
            "latency_microseconds": parts[0] if len(parts) > 0 else "",
            "observed_ttl": parts[1] if len(parts) > 1 else "",
        }
    if normalized_type == "ja4ssh":
        parts = value.split("_")
        return {
            "ja4ssh_a": parts[0] if len(parts) > 0 else "",
            "ja4ssh_b": parts[1] if len(parts) > 1 else "",
            "ja4ssh_c": parts[2] if len(parts) > 2 else "",
        }
    if normalized_type == "jarm":
        return {
            "jarm_first_30": value[:30],
            "jarm_last_32": value[30:62],
        }
    if normalized_type in {"ja3", "ja3s", "hassh", "hassh_server"}:
        return {"hash": value}
    if normalized_type in {"ja4d", "ja4d6"}:
        return {"value": value}
    return {"value": value}


def role_for_artifact_type(artifact_type: str) -> str:
    normalized_type = str(artifact_type or "").strip().lower()
    if normalized_type in {"ja4", "ja4h", "ja4t", "ja4l", "ja3", "hassh", "ja4d", "ja4d6"}:
        return "client"
    if normalized_type in {"ja4s", "ja4ts", "ja4ls", "ja3s", "hassh_server", "ja4x", "jarm"}:
        return "server"
    if normalized_type == "ja4ssh":
        return "session"
    return "unknown"


def build_artifact_record(artifact_type: str, artifact_value: str, *, provenance: str = "manual_input") -> dict[str, Any]:
    normalized_type = str(artifact_type or "").strip().lower()
    normalized_value = str(artifact_value or "").strip()
    return {
        "id": None,
        "artifact_type": normalized_type,
        "artifact_value": normalized_value,
        "role": role_for_artifact_type(normalized_type),
        "raw_fingerprint": None,
        "raw_original_order": None,
        "parts": breakdown_for_artifact(normalized_type, normalized_value),
        "provenance": provenance,
    }
