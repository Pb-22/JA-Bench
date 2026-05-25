from __future__ import annotations

from typing import Any

from .artifact_analysis_service import build_artifact_record
from .jarm_service import find_jarm_matches
from .match_service import find_reference_matches


SUPPORTED_HASH_TYPES = {
    "ja4",
    "ja4s",
    "ja4h",
    "ja4x",
    "ja4t",
    "ja4ts",
    "ja4l",
    "ja4ls",
    "ja4ssh",
    "ja3",
    "ja3s",
    "hassh",
    "hassh_server",
    "ja4d",
    "ja4d6",
    "jarm",
}


def analyze_hash_value(conn, artifact_type: str, artifact_value: str) -> dict[str, Any]:
    normalized_type = str(artifact_type or "").strip().lower()
    normalized_value = str(artifact_value or "").strip()
    if normalized_type not in SUPPORTED_HASH_TYPES:
        raise ValueError("Unsupported hash type")
    if not normalized_value:
        raise ValueError("Missing hash value")

    artifact = build_artifact_record(normalized_type, normalized_value)
    if normalized_type == "jarm":
        artifact["matches"] = []
        return {
            "analysis_mode": "standalone_hash",
            "artifact": artifact,
            "reference_matches": [],
            "jarm_matches": find_jarm_matches(conn, normalized_value),
        }

    reference_matches = find_reference_matches(conn, normalized_type, normalized_value, limit=12)
    artifact["matches"] = reference_matches
    return {
        "analysis_mode": "standalone_hash",
        "artifact": artifact,
        "reference_matches": reference_matches,
        "jarm_matches": [],
    }
