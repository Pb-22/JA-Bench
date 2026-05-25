from __future__ import annotations

import json
import sqlite3
from typing import Any


ANALYST_DATASET_KEY = "analyst_curated"

REFERENCE_FIELD_MAP = {
    "ja4": "fingerprint_value",
    "ja3": "fingerprint_value",
    "ja3s": "fingerprint_value",
    "hassh": "fingerprint_value",
    "hassh_server": "fingerprint_value",
    "ja4s": "ja4s_fingerprint",
    "ja4h": "ja4h_fingerprint",
    "ja4x": "ja4x_fingerprint",
    "ja4t": "ja4t_fingerprint",
    "ja4ts": "ja4t_fingerprint",
    "ja4l": "fingerprint_value",
    "ja4ls": "fingerprint_value",
    "ja4ssh": "fingerprint_value",
    "ja4d": "fingerprint_value",
    "ja4d6": "fingerprint_value",
}


def save_reference_from_artifact(
    conn: sqlite3.Connection,
    artifact_id: int,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = payload or {}
    artifact_row = conn.execute(
        """
        SELECT pa.*, pr.packet_number, pr.dst_ip, pr.dst_port, pr.endpoint_text
        FROM packet_artifacts pa
        JOIN packet_rows pr ON pr.id = pa.packet_id
        WHERE pa.id = ?
        """,
        (artifact_id,),
    ).fetchone()
    if not artifact_row:
        raise ValueError("Artifact not found")

    artifact = dict(artifact_row)
    artifact_type = str(artifact["artifact_type"] or "").strip().lower()
    if artifact_type not in REFERENCE_FIELD_MAP:
        raise ValueError("Artifact type is not saveable to the reference table")

    siblings = conn.execute(
        """
        SELECT artifact_type, artifact_value
        FROM packet_artifacts
        WHERE packet_id = ?
        ORDER BY id
        """,
        (artifact["packet_id"],),
    ).fetchall()
    sibling_map = {
        str(row["artifact_type"] or "").strip().lower(): str(row["artifact_value"] or "").strip()
        for row in siblings
        if row.get("artifact_type")
    }

    record_source = {
        "saved_from": "packet_artifact",
        "source_artifact_id": artifact_id,
        "source_packet_id": artifact["packet_id"],
        "source_sample_id": artifact["sample_id"],
        "source_packet_number": artifact["packet_number"],
        "destination_ip": artifact["dst_ip"],
        "destination_port": artifact["dst_port"],
        "endpoint_text": artifact["endpoint_text"],
        "known_row_artifacts": sibling_map,
        "destination_domain": str(data.get("destination_domain") or "").strip() or None,
        "analyst_note": str(data.get("analyst_note") or "").strip() or None,
    }
    return save_reference_entry(
        conn,
        {
            **data,
            "artifact_type": artifact_type,
            "artifact_value": str(data.get("artifact_value") or artifact["artifact_value"] or "").strip(),
            "record_source": record_source,
        },
        sibling_map=sibling_map,
    )


def save_reference_entry(
    conn: sqlite3.Connection,
    payload: dict[str, Any] | None = None,
    *,
    sibling_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    data = payload or {}
    artifact_type = str(data.get("artifact_type") or "").strip().lower()
    if artifact_type not in REFERENCE_FIELD_MAP:
        raise ValueError("Artifact type is not saveable to the reference table")

    target_value = str(data.get("artifact_value") or "").strip()
    if not target_value:
        raise ValueError("Missing fingerprint value to save")

    related_map = sibling_map or {}
    dataset_id = _get_or_create_dataset(conn)
    target_field = REFERENCE_FIELD_MAP[artifact_type]

    existing = conn.execute(
        f"""
        SELECT id
        FROM reference_fingerprints
        WHERE dataset_id = ? AND fingerprint_type = ? AND {target_field} = ?
        LIMIT 1
        """,
        (dataset_id, artifact_type, target_value),
    ).fetchone()
    if existing:
        return {
            "inserted": False,
            "reference_id": int(existing["id"]),
            "artifact_type": artifact_type,
            "artifact_value": target_value,
        }

    related = {
        "ja4": _pick_value(data, related_map, "ja4", fallback=target_value if artifact_type == "ja4" else ""),
        "ja4s": _pick_value(data, related_map, "ja4s"),
        "ja4h": _pick_value(data, related_map, "ja4h"),
        "ja4x": _pick_value(data, related_map, "ja4x"),
        "ja4t": _pick_value(data, related_map, "ja4t", "ja4ts", fallback=target_value if artifact_type in {"ja4t", "ja4ts"} else ""),
    }

    record_source = data.get("record_source")
    if not isinstance(record_source, dict):
        record_source = {
            "saved_from": "standalone_hash",
            "artifact_type": artifact_type,
            "artifact_value": target_value,
            "destination_domain": _clean_text(data.get("destination_domain")),
            "analyst_note": _clean_text(data.get("analyst_note")),
        }

    cur = conn.execute(
        """
        INSERT INTO reference_fingerprints (
            dataset_id,
            fingerprint_type,
            fingerprint_value,
            related_fingerprint_string,
            application,
            library_name,
            device_name,
            os_name,
            user_agent_string,
            certificate_authority,
            ja4s_fingerprint,
            ja4h_fingerprint,
            ja4x_fingerprint,
            ja4t_fingerprint,
            record_source_json,
            confidence_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            dataset_id,
            artifact_type,
            related["ja4"] or target_value,
            _related_fingerprint_string(related),
            _clean_text(data.get("application")),
            _clean_text(data.get("library_name")),
            _clean_text(data.get("device_name")),
            _clean_text(data.get("os_name")),
            _clean_text(data.get("user_agent_string")),
            _clean_text(data.get("certificate_authority")),
            related["ja4s"] or None,
            related["ja4h"] or None,
            related["ja4x"] or None,
            related["ja4t"] or None,
            json.dumps(record_source),
            _clean_text(data.get("analyst_note")),
        ),
    )
    return {
        "inserted": True,
        "reference_id": cur.lastrowid,
        "artifact_type": artifact_type,
        "artifact_value": target_value,
    }


def _get_or_create_dataset(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT id FROM reference_datasets WHERE dataset_key = ? LIMIT 1",
        (ANALYST_DATASET_KEY,),
    ).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute(
        """
        INSERT INTO reference_datasets (
            dataset_key,
            display_name,
            description,
            source,
            version,
            is_historical,
            license_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ANALYST_DATASET_KEY,
            "Analyst Curated",
            "Local analyst-saved network fingerprint records from packet review or direct hash analysis.",
            "local_manual_entry",
            "v1",
            0,
            "Local analyst-authored reference entries",
        ),
    )
    return cur.lastrowid


def _pick_value(data: dict[str, Any], siblings: dict[str, str], *keys: str, fallback: str = "") -> str:
    for key in keys:
        value = str(data.get(key) or "").strip()
        if value:
            return value
    for key in keys:
        value = str(siblings.get(key) or "").strip()
        if value:
            return value
    return fallback


def _related_fingerprint_string(values: dict[str, str]) -> str | None:
    parts = []
    for key in ("ja4", "ja4s", "ja4h", "ja4x", "ja4t"):
        value = str(values.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def _clean_text(value: Any) -> str | None:
    cleaned = str(value or "").strip()
    return cleaned or None
