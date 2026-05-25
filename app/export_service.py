from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_FORMATS = {"csv", "json", "jsonl"}
SUPPORTED_SCOPES = {"references", "jarm", "analyst_tables"}


def create_export(
    conn,
    db_path: Path,
    output_dir: Path,
    export_name: str,
    export_format: str,
    scope: str,
    sample_id: int | None = None,
) -> dict[str, Any]:
    del db_path
    del sample_id

    export_format = str(export_format or "").strip().lower()
    scope = str(scope or "").strip().lower()
    if export_format not in SUPPORTED_FORMATS:
        raise ValueError("Unsupported export format")
    if scope not in SUPPORTED_SCOPES:
        raise ValueError("Unsupported export scope")

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = _normalize_export_name(export_name)
    extension = "json" if export_format == "json" else "jsonl" if export_format == "jsonl" else "csv"
    output_path = output_dir / f"{base_name}.{extension}"

    export_bundle = _build_export_bundle(conn, scope)
    if export_format == "json":
        output_path.write_text(json.dumps(export_bundle, indent=2, sort_keys=True), encoding="utf-8")
    elif export_format == "jsonl":
        _write_jsonl(output_path, _bundle_jsonl_rows(export_bundle))
    else:
        _write_csv(output_path, _bundle_csv_rows(export_bundle))
    return _result(output_path, export_format, scope)


def _build_export_bundle(conn, scope: str) -> dict[str, Any]:
    datasets = _reference_datasets(conn) if scope in {"references", "analyst_tables"} else []
    references = _reference_fingerprints(conn) if scope in {"references", "analyst_tables"} else []
    jarm_rows = _saved_jarm_rows(conn) if scope in {"jarm", "analyst_tables"} else []
    return {
        "export_type": "ja-bench-analyst-tables",
        "scope": scope,
        "generated_at": _utc_timestamp(),
        "reference_dataset_count": len(datasets),
        "reference_count": len(references),
        "jarm_count": len(jarm_rows),
        "reference_datasets": datasets,
        "reference_fingerprints": references,
        "jarm_fingerprints": jarm_rows,
    }


def _reference_datasets(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM reference_datasets
        ORDER BY is_historical DESC, id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _reference_fingerprints(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            rf.*,
            rd.dataset_key,
            rd.display_name AS dataset_display_name,
            rd.source AS dataset_source,
            rd.source_date AS dataset_source_date,
            rd.version AS dataset_version,
            rd.is_historical AS dataset_is_historical,
            rd.license_note AS dataset_license_note
        FROM reference_fingerprints rf
        JOIN reference_datasets rd ON rd.id = rf.dataset_id
        ORDER BY rf.id
        """
    ).fetchall()
    records = []
    for row in rows:
        item = dict(row)
        item["record_source"] = _loads(item.get("record_source_json"), {})
        item.pop("record_source_json", None)
        records.append(item)
    return records


def _saved_jarm_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM jarm_fingerprints
        ORDER BY id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _bundle_csv_rows(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for dataset in bundle.get("reference_datasets") or []:
        rows.append(
            {
                "record_type": "reference_dataset",
                "scope": bundle.get("scope"),
                "dataset_id": dataset.get("id"),
                "dataset_key": dataset.get("dataset_key"),
                "dataset_display_name": dataset.get("display_name"),
                "dataset_description": dataset.get("description"),
                "dataset_source": dataset.get("source"),
                "dataset_source_date": dataset.get("source_date"),
                "dataset_version": dataset.get("version"),
                "dataset_is_historical": dataset.get("is_historical"),
                "dataset_license_note": dataset.get("license_note"),
                "created_at": dataset.get("created_at"),
            }
        )

    for reference in bundle.get("reference_fingerprints") or []:
        rows.append(
            {
                "record_type": "reference_fingerprint",
                "scope": bundle.get("scope"),
                "reference_id": reference.get("id"),
                "dataset_id": reference.get("dataset_id"),
                "dataset_key": reference.get("dataset_key"),
                "dataset_display_name": reference.get("dataset_display_name"),
                "dataset_is_historical": reference.get("dataset_is_historical"),
                "fingerprint_type": reference.get("fingerprint_type"),
                "fingerprint_value": reference.get("fingerprint_value"),
                "related_fingerprint_string": reference.get("related_fingerprint_string"),
                "application": reference.get("application"),
                "library_name": reference.get("library_name"),
                "device_name": reference.get("device_name"),
                "os_name": reference.get("os_name"),
                "user_agent_string": reference.get("user_agent_string"),
                "certificate_authority": reference.get("certificate_authority"),
                "ja4s_fingerprint": reference.get("ja4s_fingerprint"),
                "ja4h_fingerprint": reference.get("ja4h_fingerprint"),
                "ja4x_fingerprint": reference.get("ja4x_fingerprint"),
                "ja4t_fingerprint": reference.get("ja4t_fingerprint"),
                "confidence_note": reference.get("confidence_note"),
                "record_source": reference.get("record_source"),
                "created_at": reference.get("created_at"),
            }
        )

    for jarm_row in bundle.get("jarm_fingerprints") or []:
        rows.append(
            {
                "record_type": "jarm_fingerprint",
                "scope": bundle.get("scope"),
                "jarm_id": jarm_row.get("id"),
                "source_packet_id": jarm_row.get("source_packet_id"),
                "source_sample_id": jarm_row.get("source_sample_id"),
                "target_host": jarm_row.get("target_host"),
                "target_ip": jarm_row.get("target_ip"),
                "target_port": jarm_row.get("target_port"),
                "destination_domain": jarm_row.get("destination_domain"),
                "jarm_fingerprint": jarm_row.get("jarm_fingerprint"),
                "jarm_first_30": jarm_row.get("jarm_first_30"),
                "jarm_last_32": jarm_row.get("jarm_last_32"),
                "jarm_raw": jarm_row.get("jarm_raw"),
                "analyst_note": jarm_row.get("analyst_note"),
                "created_at": jarm_row.get("created_at"),
            }
        )

    return rows


def _bundle_jsonl_rows(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for dataset in bundle.get("reference_datasets") or []:
        rows.append(
            {
                "export_type": bundle.get("export_type"),
                "scope": bundle.get("scope"),
                "record_type": "reference_dataset",
                "dataset": dataset,
            }
        )

    for reference in bundle.get("reference_fingerprints") or []:
        rows.append(
            {
                "export_type": bundle.get("export_type"),
                "scope": bundle.get("scope"),
                "record_type": "reference_fingerprint",
                "reference": reference,
            }
        )

    for jarm_row in bundle.get("jarm_fingerprints") or []:
        rows.append(
            {
                "export_type": bundle.get("export_type"),
                "scope": bundle.get("scope"),
                "record_type": "jarm_fingerprint",
                "jarm": jarm_row,
            }
        )

    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    normalized_rows = rows or [{}]
    fieldnames: list[str] = []
    for row in normalized_rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in normalized_rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _loads(value: Any, fallback: Any = None) -> Any:
    if value in (None, ""):
        return {} if fallback is None else fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {} if fallback is None else fallback


def _normalize_export_name(value: str) -> str:
    text = str(value or "").strip().lower()
    safe = []
    for char in text:
        if char.isalnum():
            safe.append(char)
        elif char in {"-", "_", "."}:
            safe.append(char)
        elif char.isspace():
            safe.append("-")
    normalized = "".join(safe).strip("-.")
    if not normalized:
        normalized = f"ja-bench-export-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    return normalized


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _result(output_path: Path, export_format: str, scope: str) -> dict[str, Any]:
    return {
        "format": export_format,
        "scope": scope,
        "filename": output_path.name,
        "output_path": str(output_path),
    }
