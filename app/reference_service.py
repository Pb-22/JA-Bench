from __future__ import annotations

import sqlite3
from typing import Any


def search_reference_fingerprints(
    conn: sqlite3.Connection,
    fingerprint_value: str,
    fingerprint_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(limit, 200))
    params: list[Any] = [fingerprint_value]
    sql = """
        SELECT
            rf.id,
            rd.dataset_key,
            rd.display_name AS dataset_name,
            rd.is_historical,
            rf.fingerprint_type,
            rf.fingerprint_value,
            rf.related_fingerprint_string,
            rf.application,
            rf.library_name,
            rf.device_name,
            rf.os_name,
            rf.user_agent_string,
            rf.certificate_authority,
            rf.ja4s_fingerprint,
            rf.ja4h_fingerprint,
            rf.ja4x_fingerprint,
            rf.ja4t_fingerprint,
            rf.confidence_note
        FROM reference_fingerprints rf
        JOIN reference_datasets rd ON rd.id = rf.dataset_id
        WHERE rf.fingerprint_value = ?
    """
    if fingerprint_type:
        sql += " AND rf.fingerprint_type = ?"
        params.append(fingerprint_type)
    sql += " ORDER BY rf.application IS NULL, rf.application, rf.os_name, rf.device_name LIMIT ?"
    params.append(bounded_limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
