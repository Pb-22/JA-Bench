from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


JARM_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "vendor" / "jarm" / "jarm.py"


def run_jarm_enrichment(target_host: str, target_port: int) -> dict[str, Any]:
    host = str(target_host or "").strip()
    if not host:
        raise ValueError("Missing target host for JARM enrichment")
    port = int(target_port or 443)

    cmd = ["python3", str(JARM_SCRIPT_PATH), "-p", str(port), "-j", "-v", host]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=45)
    if proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(stderr or "JARM command failed")

    line = next((item for item in reversed(proc.stdout.splitlines()) if item.strip()), "")
    if not line:
        raise RuntimeError("JARM command returned no output")
    payload = json.loads(line)
    fingerprint = str(payload.get("result") or "").strip()
    if len(fingerprint) != 62:
        raise RuntimeError("JARM result was not the expected 62-character fingerprint")

    result = {
        "target_host": host,
        "resolved_ip": payload.get("ip"),
        "target_port": port,
        "jarm_fingerprint": fingerprint,
        "jarm_first_30": fingerprint[:30],
        "jarm_last_32": fingerprint[30:],
        "jarm_raw": payload.get("jarm"),
        "notes": _build_jarm_notes(fingerprint),
    }
    result["matches"] = []
    return result


def find_jarm_matches(conn: sqlite3.Connection, fingerprint: str) -> list[dict[str, Any]]:
    value = str(fingerprint or "").strip()
    if len(value) != 62:
        return []
    first = value[:30]
    last = value[30:]
    rows = conn.execute(
        """
        SELECT *
        FROM jarm_fingerprints
        WHERE jarm_fingerprint = ? OR jarm_first_30 = ? OR jarm_last_32 = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 25
        """,
        (value, first, last),
    ).fetchall()
    matches = []
    for row in rows:
        stored = str(row["jarm_fingerprint"] or "")
        if stored == value:
            match_kind = "exact"
            note = "Full JARM fingerprint match"
        elif str(row["jarm_first_30"] or "") == first:
            match_kind = "first_30"
            note = "First 30 characters match, so the negotiated version and cipher behavior across the 10 probes aligns."
        elif str(row["jarm_last_32"] or "") == last:
            match_kind = "last_32"
            note = "Last 32 characters match, so the hashed extension behavior aligns even though the first half differs."
        else:
            continue
        matches.append(
            {
                "match_kind": match_kind,
                "note": note,
                "saved": dict(row),
            }
        )
    matches.sort(key=_match_sort_key)
    return matches


def save_jarm_fingerprint(
    conn: sqlite3.Connection,
    packet_id: int,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    packet = conn.execute(
        """
        SELECT id, sample_id, dst_ip, dst_port
        FROM packet_rows
        WHERE id = ?
        """,
        (packet_id,),
    ).fetchone()
    if not packet:
        raise ValueError("Packet not found")

    return save_jarm_observation(
        conn,
        payload,
        source_packet_id=packet_id,
        source_sample_id=packet["sample_id"],
        default_target_host=packet["dst_ip"],
        default_target_ip=packet["dst_ip"],
        default_target_port=packet["dst_port"],
    )


def save_jarm_observation(
    conn: sqlite3.Connection,
    payload: dict[str, Any] | None = None,
    *,
    source_packet_id: int | None = None,
    source_sample_id: int | None = None,
    default_target_host: str | None = None,
    default_target_ip: str | None = None,
    default_target_port: int | None = None,
) -> dict[str, Any]:
    data = payload or {}

    fingerprint = str(data.get("jarm_fingerprint") or "").strip()
    if len(fingerprint) != 62:
        raise ValueError("Missing valid 62-character JARM fingerprint")
    first = fingerprint[:30]
    last = fingerprint[30:]

    target_host = str(data.get("target_host") or data.get("destination_domain") or default_target_host or "").strip()
    target_ip = str(data.get("target_ip") or default_target_ip or "").strip() or None
    target_port = int(data.get("target_port") or default_target_port or 443)
    destination_domain = str(data.get("destination_domain") or "").strip() or None
    analyst_note = str(data.get("analyst_note") or "").strip() or None
    jarm_raw = str(data.get("jarm_raw") or "").strip() or None
    if not target_host:
        raise ValueError("Missing target host for JARM save")

    existing = conn.execute(
        """
        SELECT id
        FROM jarm_fingerprints
        WHERE jarm_fingerprint = ? AND ifnull(target_ip, '') = ifnull(?, '') AND target_port = ?
        LIMIT 1
        """,
        (fingerprint, target_ip, target_port),
    ).fetchone()
    if existing:
        return {
            "inserted": False,
            "jarm_id": int(existing["id"]),
            "matches": find_jarm_matches(conn, fingerprint),
        }

    cur = conn.execute(
        """
        INSERT INTO jarm_fingerprints (
            source_packet_id,
            source_sample_id,
            target_host,
            target_ip,
            target_port,
            destination_domain,
            jarm_fingerprint,
            jarm_first_30,
            jarm_last_32,
            jarm_raw,
            analyst_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_packet_id,
            source_sample_id,
            target_host,
            target_ip,
            target_port,
            destination_domain,
            fingerprint,
            first,
            last,
            jarm_raw,
            analyst_note,
        ),
    )
    return {
        "inserted": True,
        "jarm_id": cur.lastrowid,
        "matches": find_jarm_matches(conn, fingerprint),
    }


def _build_jarm_notes(fingerprint: str) -> list[str]:
    first = fingerprint[:30]
    last = fingerprint[30:]
    notes = [
        "JARM is an active TLS server fingerprint built from 10 specially crafted ClientHello probes.",
        "The first 30 characters encode the TLS version and cipher choices the server made across those 10 probes.",
        "The last 32 characters are a truncated SHA256 hash of the cumulative extension behavior, excluding X.509 certificate data.",
    ]
    if "000" in [first[index:index + 3] for index in range(0, len(first), 3)]:
        notes.append("A 000 triplet in the first half means the server refused to negotiate for at least one of the JARM probe styles.")
    if set(fingerprint) == {"0"}:
        notes.append("An all-zero JARM usually means the target did not complete meaningful TLS negotiation on the tested host and port.")
    if first and last:
        notes.append("If another JARM matches only the first 30 characters, the servers likely share version and cipher behavior but differ in extensions.")
        notes.append("If another JARM matches only the last 32 characters, the extension behavior aligns but the negotiated version and cipher choices differ.")
    return notes


def _match_sort_key(item: dict[str, Any]) -> tuple[int, int]:
    rank = {
        "exact": 0,
        "first_30": 1,
        "last_32": 2,
    }.get(str(item.get("match_kind") or ""), 9)
    return (rank, -int(item.get("saved", {}).get("id") or 0))
