from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent.parent / "seed"
JA4PLUS_CSV = SEED_DIR / "reference_ja4plus_db.csv"
HIGH_CONFIDENCE_BROWSER_CSV = SEED_DIR / "high_confidence_browser_fingerprints.csv"
DATASET_KEY = "ja4plus_historical_seed"
HIGH_CONFIDENCE_BROWSER_DATASET_KEY = "ja_bench_high_confidence_browser_fingerprints"


def load_seed_data(conn: sqlite3.Connection) -> None:
    load_reference_ja4plus(conn)
    load_high_confidence_browser_fingerprints(conn)



def load_reference_ja4plus(conn: sqlite3.Connection) -> None:
    if not JA4PLUS_CSV.exists():
        return

    existing = conn.execute(
        "SELECT id FROM reference_datasets WHERE dataset_key = ?",
        (DATASET_KEY,),
    ).fetchone()
    if existing:
        return

    cur = conn.execute(
        """
        INSERT INTO reference_datasets (
            dataset_key,
            display_name,
            description,
            source,
            source_date,
            version,
            is_historical,
            license_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            DATASET_KEY,
            "JA4+ historical starter dataset",
            "Bundled historical JA4-related starter reference data for JA-Bench.",
            "User-provided historical JA4+ CSV",
            "2026-05-23",
            "seed-v1",
            1,
            "Historical starter reference data bundled for local JA-Bench lookups.",
        ),
    )
    dataset_id = cur.lastrowid

    with JA4PLUS_CSV.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for record in reader:
            rows.append(
                (
                    dataset_id,
                    "ja4",
                    _clean(record.get("ja4_fingerprint")),
                    _clean(record.get("ja4_fingerprint_string")),
                    _clean(record.get("application")),
                    _clean(record.get("library")),
                    _clean(record.get("device")),
                    _clean(record.get("os")),
                    _clean(record.get("user_agent_string")),
                    _clean(record.get("certificate_authority")),
                    _clean(record.get("ja4s_fingerprint")),
                    _clean(record.get("ja4h_fingerprint")),
                    _clean(record.get("ja4x_fingerprint")),
                    _clean(record.get("ja4t_fingerprint")),
                    json.dumps(record, ensure_ascii=False),
                    "Historical seed record; validate against current sources when confidence matters.",
                )
            )

    conn.executemany(
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
        [row for row in rows if row[2]],
    )



def load_high_confidence_browser_fingerprints(conn: sqlite3.Connection) -> None:
    if not HIGH_CONFIDENCE_BROWSER_CSV.exists():
        return

    existing = conn.execute(
        "SELECT id FROM reference_datasets WHERE dataset_key = ?",
        (HIGH_CONFIDENCE_BROWSER_DATASET_KEY,),
    ).fetchone()
    if existing:
        return

    cur = conn.execute(
        """
        INSERT INTO reference_datasets (
            dataset_key,
            display_name,
            description,
            source,
            source_date,
            version,
            is_historical,
            license_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            HIGH_CONFIDENCE_BROWSER_DATASET_KEY,
            "JA Bench high confidence browser fingerprints",
            "Curated high confidence JA4 plus browser fingerprint candidates for reference matching.",
            "JA Bench browser fingerprint corpus review",
            "2026-06-03",
            "high-confidence-v1",
            1,
            "Bundled reference rows for local JA-Bench lookups; validate against fresh captures before broad production use.",
        ),
    )
    dataset_id = cur.lastrowid

    with HIGH_CONFIDENCE_BROWSER_CSV.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for record in reader:
            hash_type = _clean(record.get("hash_type"))
            fingerprint_value = _clean(record.get("hash"))
            if not hash_type or not fingerprint_value:
                continue
            normalized_type = hash_type.lower()
            record_source = dict(record)
            rows.append(
                (
                    dataset_id,
                    normalized_type,
                    fingerprint_value,
                    None,
                    _clean(record.get("browser")),
                    None,
                    _clean(record.get("sample")),
                    _clean(record.get("os")),
                    None,
                    None,
                    None,
                    fingerprint_value if normalized_type == "ja4h" else None,
                    None,
                    fingerprint_value if normalized_type in {"ja4t", "ja4ts"} else None,
                    json.dumps(record_source, ensure_ascii=False, sort_keys=True),
                    _high_confidence_note(record),
                )
            )

    conn.executemany(
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
        rows,
    )


def _high_confidence_note(record: dict[str, str]) -> str:
    confidence = _clean(record.get("confidence")) or "high"
    basis = _clean(record.get("confidence_basis")) or "high confidence browser fingerprint candidate"
    count = _clean(record.get("count"))
    total = _clean(record.get("total_rows_for_type_in_sample"))
    percent = _clean(record.get("percent_within_type"))
    count_note = f"; count {count} of {total} in sample" if count and total else ""
    percent_note = f"; {percent} percent within type" if percent else ""
    return f"{confidence} confidence; {basis}{count_note}{percent_note}."


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None
