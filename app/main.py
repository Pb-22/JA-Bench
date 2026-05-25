from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from .analyst_service import save_reference_entry, save_reference_from_artifact
from .config import Config
from .db import close_db, get_db
from .export_service import create_export
from .hash_analysis_service import SUPPORTED_HASH_TYPES, analyze_hash_value
from .init_db import init_db
from .jarm_service import find_jarm_matches, run_jarm_enrichment, save_jarm_fingerprint, save_jarm_observation
from .packet_enrichment_service import enrich_packet_with_shodan
from .pcap_reader_service import (
    PcapParseError,
    _refresh_sample_packet_endpoints,
    get_packet_detail,
    ingest_pcap,
)
from .shodan_service import ShodanNotConfiguredError, ShodanService


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db()

    for key in ("UPLOAD_DIR", "OUTPUT_DIR", "CACHE_DIR", "CONFIG_DIR", "ZEEK_DIR"):
        app.config[key].mkdir(parents=True, exist_ok=True)

    app.extensions["shodan_service"] = ShodanService(
        api_key=os.environ.get("SHODAN_API_KEY"),
        cache_root=app.config["CACHE_DIR"] / "shodan",
        cache_ttl_seconds=app.config["SHODAN_CACHE_TTL_SECONDS"],
    )

    app.teardown_appcontext(close_db)

    with app.app_context():
        db = get_db()
        _repair_packet_endpoints(db, app.config["UPLOAD_DIR"])
        db.commit()

    @app.route("/")
    def index():
        db = get_db()
        counts = {
            "runs": db.execute("SELECT COUNT(*) AS count FROM runs").fetchone()["count"],
            "samples": db.execute("SELECT COUNT(*) AS count FROM samples").fetchone()["count"],
            "packets": db.execute("SELECT COUNT(*) AS count FROM packet_rows").fetchone()["count"],
            "artifacts": db.execute("SELECT COUNT(*) AS count FROM packet_artifacts").fetchone()["count"],
        }
        return render_template(
            "index.html",
            counts=counts,
            db_path=str(app.config["DB_PATH"]),
            zeek_script=str(app.config["ZEEK_SCRIPT_PATH"]),
            shodan_enabled=app.config["SHODAN_ENABLED"],
        )

    @app.route("/api/upload-pcap", methods=["POST"])
    def api_upload_pcap():
        uploaded = request.files.get("pcap")
        if uploaded is None or not uploaded.filename:
            return jsonify({"error": "Missing uploaded PCAP file"}), 400

        suffix = Path(uploaded.filename).suffix or ".pcap"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp_path = Path(tmp.name)
                uploaded.save(tmp)

            db = get_db()
            result = ingest_pcap(
                db,
                source_path=tmp_path,
                original_filename=uploaded.filename,
                upload_dir=app.config["UPLOAD_DIR"],
                zeek_output_root=app.config["ZEEK_DIR"],
                zeek_script_path=app.config["ZEEK_SCRIPT_PATH"],
            )
            result["counts"] = {
                "runs": db.execute("SELECT COUNT(*) AS count FROM runs").fetchone()["count"],
                "samples": db.execute("SELECT COUNT(*) AS count FROM samples").fetchone()["count"],
                "packets": db.execute("SELECT COUNT(*) AS count FROM packet_rows").fetchone()["count"],
                "artifacts": db.execute("SELECT COUNT(*) AS count FROM packet_artifacts").fetchone()["count"],
            }
            db.commit()
            return jsonify(result)
        except PcapParseError as exc:
            db = get_db()
            db.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db = get_db()
            db.rollback()
            return jsonify({"error": f"Upload/parse failed: {exc}"}), 500
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    @app.route("/api/packets/<int:packet_id>")
    def api_packet_detail(packet_id: int):
        db = get_db()
        detail = get_packet_detail(db, packet_id)
        if detail is None:
            return jsonify({"error": "Packet not found"}), 404
        return jsonify(detail)

    @app.route("/api/artifacts/<int:artifact_id>/save-reference", methods=["POST"])
    def api_save_reference(artifact_id: int):
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            result = save_reference_from_artifact(db, artifact_id, payload)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db.rollback()
            return jsonify({"error": f"Reference save failed: {exc}"}), 500

    @app.route("/api/references/save-standalone", methods=["POST"])
    def api_save_standalone_reference():
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            result = save_reference_entry(db, payload)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db.rollback()
            return jsonify({"error": f"Reference save failed: {exc}"}), 500

    @app.route("/api/runtime-config")
    def api_runtime_config():
        return jsonify(
            {
                "shodan_enabled": bool(app.config["SHODAN_ENABLED"]),
                "shodan_cache_ttl_seconds": app.config["SHODAN_CACHE_TTL_SECONDS"],
                "db_path": str(app.config["DB_PATH"]),
            }
        )

    @app.route("/api/export", methods=["POST"])
    def api_export():
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            export_info = create_export(
                db,
                db_path=app.config["DB_PATH"],
                output_dir=app.config["OUTPUT_DIR"] / "exports",
                export_name=str(payload.get("export_name") or ""),
                export_format=str(payload.get("export_format") or ""),
                scope=str(payload.get("scope") or ""),
                sample_id=int(payload["sample_id"]) if payload.get("sample_id") not in (None, "") else None,
            )
            return send_file(
                export_info["output_path"],
                as_attachment=True,
                download_name=export_info["filename"],
                max_age=0,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Export failed: {exc}"}), 500

    @app.route("/api/hash-analysis", methods=["POST"])
    def api_hash_analysis():
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            result = analyze_hash_value(
                db,
                artifact_type=str(payload.get("artifact_type") or ""),
                artifact_value=str(payload.get("artifact_value") or ""),
            )
            result["supported_hash_types"] = sorted(SUPPORTED_HASH_TYPES)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Hash analysis failed: {exc}"}), 500

    @app.route("/api/shodan/configure", methods=["POST"])
    def api_shodan_configure():
        payload = request.get_json(silent=True) or {}
        api_key = str(payload.get("api_key") or "").strip()
        if not api_key:
            return jsonify({"error": "Missing Shodan API key"}), 400
        try:
            info = _activate_shodan_key(app, api_key)
            return jsonify(
                {
                    "configured": True,
                    "info": {
                        "plan": info.get("plan"),
                        "https": info.get("https"),
                        "query_credits": info.get("query_credits"),
                        "scan_credits": info.get("scan_credits"),
                    },
                }
            )
        except Exception as exc:
            return jsonify({"error": f"Shodan key test failed: {exc}"}), 400

    @app.route("/api/packets/<int:packet_id>/jarm-enrich", methods=["POST"])
    def api_jarm_enrich(packet_id: int):
        db = get_db()
        packet = get_packet_detail(db, packet_id)
        if packet is None:
            return jsonify({"error": "Packet not found"}), 404
        payload = request.get_json(silent=True) or {}
        try:
            target_host = payload.get("target_host")
            target_port = int(payload.get("target_port") or packet["packet"].get("dst_port") or 443)
            result = run_jarm_enrichment(str(target_host or ""), target_port)
            result["matches"] = find_jarm_matches(db, result["jarm_fingerprint"])
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"JARM enrichment failed: {exc}"}), 500

    @app.route("/api/packets/<int:packet_id>/shodan-enrich", methods=["POST"])
    def api_shodan_enrich(packet_id: int):
        db = get_db()
        detail = get_packet_detail(db, packet_id)
        if detail is None:
            return jsonify({"error": "Packet not found"}), 404
        shodan_service = app.extensions["shodan_service"]
        payload = request.get_json(silent=True) or {}
        force_refresh = bool(payload.get("force_refresh"))
        try:
            result = enrich_packet_with_shodan(
                shodan_service,
                detail["packet"],
                detail["packet"].get("packet_inspector"),
                force_refresh=force_refresh,
            )
            return jsonify(result)
        except ShodanNotConfiguredError as exc:
            return jsonify({"error": str(exc)}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Shodan enrichment failed: {exc}"}), 500

    @app.route("/api/packets/<int:packet_id>/save-jarm", methods=["POST"])
    def api_save_jarm(packet_id: int):
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            result = save_jarm_fingerprint(db, packet_id, payload)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db.rollback()
            return jsonify({"error": f"JARM save failed: {exc}"}), 500

    @app.route("/api/jarm/save-standalone", methods=["POST"])
    def api_save_standalone_jarm():
        db = get_db()
        payload = request.get_json(silent=True) or {}
        try:
            result = save_jarm_observation(db, payload)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            db.rollback()
            return jsonify({"error": f"JARM save failed: {exc}"}), 500

    @app.route("/healthz")
    def healthz():
        db = get_db()
        db.execute("SELECT 1")
        return {"status": "ok"}

    return app


def _activate_shodan_key(app: Flask, api_key: str) -> dict:
    service = ShodanService(
        api_key=api_key,
        cache_root=app.config["CACHE_DIR"] / "shodan",
        cache_ttl_seconds=app.config["SHODAN_CACHE_TTL_SECONDS"],
    )
    info = service.info(force_refresh=True).value
    _persist_shodan_key(app.config["CONFIG_DIR"], api_key)
    os.environ["SHODAN_API_KEY"] = api_key
    app.config["SHODAN_ENABLED"] = True
    app.extensions["shodan_service"] = service
    subprocess.run(["shodan", "init", api_key], capture_output=True, text=True, check=False)
    return info


def _persist_shodan_key(config_dir: Path, api_key: str) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / "keys.env"
    target.write_text(
        "# Local optional keys for JA-Bench\n"
        "# This file is gitignored and is loaded by the container entrypoint.\n\n"
        f"SHODAN_API_KEY={api_key}\n",
        encoding="utf-8",
    )


def _repair_packet_endpoints(db, upload_dir: Path) -> None:
    sample_rows = db.execute(
        """
        SELECT DISTINCT sample_id
        FROM packet_rows
        WHERE endpoint_text = 'unknown -> unknown'
           OR endpoint_text LIKE 'unknown -> %'
           OR endpoint_text LIKE '% -> unknown'
        """
    ).fetchall()
    for row in sample_rows:
        _refresh_sample_packet_endpoints(db, int(row["sample_id"]), upload_dir)
