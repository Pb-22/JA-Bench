from __future__ import annotations

import json
import sqlite3
from typing import Any


SECTION_LABELS = {
    "ja4": ["ja4_a", "ja4_b", "ja4_c"],
    "ja4s": ["ja4s_a", "ja4s_b", "ja4s_c"],
    "ja4h": ["ja4h_a", "ja4h_b", "ja4h_c", "ja4h_d"],
    "ja4x": ["ja4x_a", "ja4x_b", "ja4x_c"],
    "ja4t": ["ja4t_a", "ja4t_b", "ja4t_c", "ja4t_d"],
    "ja4ts": ["ja4ts_a", "ja4ts_b", "ja4ts_c", "ja4ts_d"],
}


def store_artifact_matches(
    conn: sqlite3.Connection,
    artifact_id: int,
    artifact_type: str,
    artifact_value: str,
) -> list[dict[str, Any]]:
    normalized_type = (artifact_type or "").strip().lower()
    normalized_value = (artifact_value or "").strip()
    if not normalized_value:
        return []

    matches = find_reference_matches(conn, normalized_type, normalized_value)
    if not matches:
        return []

    rows = []
    for match in matches:
        cur = conn.execute(
            """
            INSERT INTO artifact_matches (
                artifact_id,
                reference_id,
                match_kind,
                matched_section_count,
                matched_sections_json,
                note
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                match["reference"]["id"],
                match["match_kind"],
                len(match["matched_sections"]),
                json.dumps(match["matched_sections"]),
                match["note"],
            ),
        )
        rows.append({**match, "id": cur.lastrowid})
    return rows


def hydrate_artifact_matches(conn: sqlite3.Connection, artifact_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            am.id,
            am.match_kind,
            am.matched_section_count,
            am.matched_sections_json,
            am.note,
            pa.artifact_type,
            pa.artifact_value,
            rf.id AS reference_id,
            rd.display_name AS dataset_name,
            rf.application,
            rf.library_name,
            rf.device_name,
            rf.os_name,
            rf.user_agent_string,
            rf.certificate_authority,
            rf.fingerprint_value,
            rf.ja4s_fingerprint,
            rf.ja4h_fingerprint,
            rf.ja4x_fingerprint,
            rf.ja4t_fingerprint,
            rf.related_fingerprint_string,
            rf.confidence_note
        FROM artifact_matches am
        JOIN packet_artifacts pa ON pa.id = am.artifact_id
        JOIN reference_fingerprints rf ON rf.id = am.reference_id
        JOIN reference_datasets rd ON rd.id = rf.dataset_id
        WHERE am.artifact_id = ?
        ORDER BY
            CASE am.match_kind WHEN 'exact' THEN 0 ELSE 1 END,
            am.matched_section_count DESC,
            rf.application,
            rf.os_name,
            rf.device_name
        """,
        (artifact_id,),
    ).fetchall()
    hydrated = []
    for row in rows:
        matched_sections = _loads(row["matched_sections_json"], [])
        if row["match_kind"] == "partial" and not _partial_match_allowed(str(row["artifact_type"] or ""), matched_sections):
            continue
        reference = {
            "id": row["reference_id"],
            "dataset_name": row["dataset_name"],
            "application": row["application"],
            "library_name": row["library_name"],
            "device_name": row["device_name"],
            "os_name": row["os_name"],
            "user_agent_string": row["user_agent_string"],
            "certificate_authority": row["certificate_authority"],
            "fingerprint_value": row["fingerprint_value"],
            "ja4s_fingerprint": row["ja4s_fingerprint"],
            "ja4h_fingerprint": row["ja4h_fingerprint"],
            "ja4x_fingerprint": row["ja4x_fingerprint"],
            "ja4t_fingerprint": row["ja4t_fingerprint"],
            "related_fingerprint_string": row["related_fingerprint_string"],
            "confidence_note": row["confidence_note"],
        }
        reference_value = _reference_value_for_type(str(row["artifact_type"] or ""), reference)
        hydrated.append(
            {
                "id": row["id"],
                "match_kind": row["match_kind"],
                "matched_section_count": row["matched_section_count"],
                "matched_sections": matched_sections,
                "matched_fields": _matched_field_details(
                    str(row["artifact_type"] or ""),
                    str(row["artifact_value"] or ""),
                    reference_value,
                    None if row["match_kind"] == "exact" else matched_sections,
                ),
                "note": row["note"],
                "reference": reference,
            }
        )
    return hydrated


def find_reference_matches(
    conn: sqlite3.Connection,
    artifact_type: str,
    artifact_value: str,
    limit: int = 8,
) -> list[dict[str, Any]]:
    selector = _selector_for_type(artifact_type)
    if selector is None:
        return []

    rows = conn.execute(selector["sql"]).fetchall()
    matches: list[dict[str, Any]] = []
    artifact_sections = _split_sections(artifact_type, artifact_value)

    for row in rows:
        candidate_value = row[selector["field"]]
        if not candidate_value:
            continue
        matched_sections = _matching_sections(artifact_type, artifact_sections, _split_sections(artifact_type, candidate_value))
        if candidate_value == artifact_value:
            matches.append(
                {
                    "match_kind": "exact",
                    "matched_sections": SECTION_LABELS.get(artifact_type, []),
                    "matched_fields": _matched_field_details(artifact_type, artifact_value, candidate_value),
                    "note": "Match found",
                    "reference": dict(row),
                }
            )
            continue
        if matched_sections and _partial_match_allowed(artifact_type, matched_sections):
            note = "Partial match found" if len(matched_sections) == 1 else "Multi-section partial match found"
            matches.append(
                {
                    "match_kind": "partial",
                    "matched_sections": matched_sections,
                    "matched_fields": _matched_field_details(artifact_type, artifact_value, candidate_value, matched_sections),
                    "note": note,
                    "reference": dict(row),
                }
            )

    matches.sort(
        key=lambda item: (
            0 if item["match_kind"] == "exact" else 1,
            -len(item["matched_sections"]),
            str(item["reference"].get("application") or ""),
            str(item["reference"].get("os_name") or ""),
        )
    )
    return matches[:limit]


def _selector_for_type(artifact_type: str) -> dict[str, str] | None:
    base_sql = """
        SELECT
            rf.id,
            rd.display_name AS dataset_name,
            rf.application,
            rf.library_name,
            rf.device_name,
            rf.os_name,
            rf.user_agent_string,
            rf.certificate_authority,
            rf.fingerprint_value,
            rf.ja4s_fingerprint,
            rf.ja4h_fingerprint,
            rf.ja4x_fingerprint,
            rf.ja4t_fingerprint,
            rf.related_fingerprint_string,
            rf.confidence_note
        FROM reference_fingerprints rf
        JOIN reference_datasets rd ON rd.id = rf.dataset_id
    """
    mapping = {
        "ja4": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4'"},
        "ja3": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja3'"},
        "ja3s": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja3s'"},
        "hassh": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'hassh'"},
        "hassh_server": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'hassh_server'"},
        "ja4s": {"field": "ja4s_fingerprint", "where": "rf.ja4s_fingerprint IS NOT NULL"},
        "ja4h": {"field": "ja4h_fingerprint", "where": "rf.ja4h_fingerprint IS NOT NULL"},
        "ja4x": {"field": "ja4x_fingerprint", "where": "rf.ja4x_fingerprint IS NOT NULL"},
        "ja4t": {"field": "ja4t_fingerprint", "where": "rf.ja4t_fingerprint IS NOT NULL"},
        "ja4ts": {"field": "ja4t_fingerprint", "where": "rf.ja4t_fingerprint IS NOT NULL"},
        "ja4l": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4l'"},
        "ja4ls": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4ls'"},
        "ja4ssh": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4ssh'"},
        "ja4d": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4d'"},
        "ja4d6": {"field": "fingerprint_value", "where": "rf.fingerprint_type = 'ja4d6'"},
    }
    entry = mapping.get(artifact_type)
    if not entry:
        return None
    return {"field": entry["field"], "sql": f"{base_sql} WHERE {entry['where']}"}


def _split_sections(artifact_type: str, value: str) -> list[str]:
    if artifact_type in {"ja4l", "ja4ls"}:
        _, _, rhs = value.partition("=")
        return rhs.split("_") if rhs else []
    return value.split("_")


def _matching_sections(artifact_type: str, left: list[str], right: list[str]) -> list[str]:
    labels = SECTION_LABELS.get(artifact_type, [])
    matched = []
    for index, (left_value, right_value) in enumerate(zip(left, right)):
        if left_value and right_value and left_value == right_value:
            matched.append(labels[index] if index < len(labels) else f"section_{index + 1}")
    return matched


def _partial_match_allowed(artifact_type: str, matched_sections: list[str]) -> bool:
    if not matched_sections:
        return False
    if artifact_type == "ja4h":
        return matched_sections in (
            ["ja4h_a", "ja4h_b"],
            ["ja4h_a", "ja4h_b", "ja4h_c"],
        )
    if artifact_type in {"ja4t", "ja4ts"}:
        return len(matched_sections) > 1
    return True


def _matched_field_details(
    artifact_type: str,
    artifact_value: str,
    reference_value: str,
    matched_sections: list[str] | None = None,
) -> list[dict[str, str]]:
    labels = SECTION_LABELS.get(artifact_type, [])
    observed_parts = _split_sections(artifact_type, artifact_value)
    reference_parts = _split_sections(artifact_type, reference_value)
    section_filter = set(matched_sections or labels)
    details: list[dict[str, str]] = []

    for index, label in enumerate(labels):
        if label not in section_filter:
            continue
        observed = observed_parts[index] if index < len(observed_parts) else ""
        reference = reference_parts[index] if index < len(reference_parts) else ""
        if not observed or not reference or observed != reference:
            continue
        details.append(
            {
                "label": label,
                "value": observed,
            }
        )
    return details


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _reference_value_for_type(artifact_type: str, reference: dict[str, Any]) -> str:
    normalized = (artifact_type or "").strip().lower()
    if normalized == "ja4":
        return str(reference.get("fingerprint_value") or "")
    if normalized == "ja4s":
        return str(reference.get("ja4s_fingerprint") or "")
    if normalized == "ja4h":
        return str(reference.get("ja4h_fingerprint") or "")
    if normalized == "ja4x":
        return str(reference.get("ja4x_fingerprint") or "")
    if normalized in {"ja4t", "ja4ts"}:
        return str(reference.get("ja4t_fingerprint") or "")
    return ""
