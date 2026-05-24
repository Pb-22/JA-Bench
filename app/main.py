from __future__ import annotations

import os
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory

from .config import Config
from .db import close_db, get_db
from .shodan_service import ShodanNotConfiguredError, ShodanService
from .reference_service import search_reference_fingerprints
from .search_service import local_search
from .pcap_service import PcapParseError, ingest_pcap
from .flow_detail_service import get_flow_detail
from .init_db import init_db
from .export_service import create_export
from .enrichment_service import enrich_flow_with_shodan
from .light_probe_service import run_light_http_metadata_probe, run_light_jarm_probe, run_light_tls_cert_grab, run_pcap_mimic_request


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db()

    for key in ("UPLOAD_DIR", "OUTPUT_DIR", "CACHE_DIR", "CONFIG_DIR"):
        app.config[key].mkdir(parents=True, exist_ok=True)

    app.extensions["shodan_service"] = ShodanService(
        api_key=os.environ.get("SHODAN_API_KEY"),
        cache_root=app.config["CACHE_DIR"] / "shodan",
        cache_ttl_seconds=app.config["SHODAN_CACHE_TTL_SECONDS"],
    )

    app.teardown_appcontext(close_db)

    @app.route("/")
    def index():
        db = get_db()
        counts = {
            "runs": db.execute("SELECT COUNT(*) AS count FROM runs").fetchone()["count"],
            "samples": db.execute("SELECT COUNT(*) AS count FROM samples").fetchone()["count"],
            "flows": db.execute("SELECT COUNT(*) AS count FROM flows").fetchone()["count"],
            "fingerprints": db.execute("SELECT COUNT(*) AS count FROM fingerprints").fetchone()["count"],
        }
        return render_template(
            "index.html",
            counts=counts,
            db_path=str(app.config["DB_PATH"]),
            shodan_enabled=app.config["SHODAN_ENABLED"],
            shodan_cache_ttl_seconds=app.config["SHODAN_CACHE_TTL_SECONDS"],
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
                mode="passive",
            )
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

    @app.route("/api/flows/<int:flow_id>")
    def api_flow_detail(flow_id: int):
        db = get_db()
        detail = get_flow_detail(db, flow_id)
        if detail is None:
            return jsonify({"error": "Flow not found"}), 404
        return jsonify(detail)

    @app.route("/api/reference-search")
    def api_reference_search():
        fingerprint_value = (request.args.get("value") or "").strip()
        fingerprint_type = (request.args.get("type") or "").strip() or 'auto'
        if not fingerprint_value:
            return jsonify({"error": "Missing required query parameter: value"}), 400
        db = get_db()
        try:
            return jsonify(local_search(db, fingerprint_value, search_type=fingerprint_type))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route('/api/flows/<int:flow_id>/probe/jarm', methods=['POST'])
    def api_flow_probe_jarm(flow_id: int):
        db = get_db()
        force_refresh = bool((request.get_json(silent=True) or {}).get('force_refresh'))
        try:
            result = run_light_jarm_probe(
                db,
                vendor_root=Path(app.root_path).parent / 'vendor',
                flow_id=flow_id,
                force_refresh=force_refresh,
            )
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 404
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'Light-testing JARM probe failed: {exc}'}), 500

    @app.route('/api/flows/<int:flow_id>/probe/tls-cert', methods=['POST'])
    def api_flow_probe_tls_cert(flow_id: int):
        db = get_db()
        force_refresh = bool((request.get_json(silent=True) or {}).get('force_refresh'))
        try:
            result = run_light_tls_cert_grab(db, flow_id=flow_id, force_refresh=force_refresh)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 404
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'Light-testing TLS cert grab failed: {exc}'}), 500

    @app.route('/api/flows/<int:flow_id>/probe/http-metadata', methods=['POST'])
    def api_flow_probe_http_metadata(flow_id: int):
        db = get_db()
        force_refresh = bool((request.get_json(silent=True) or {}).get('force_refresh'))
        try:
            result = run_light_http_metadata_probe(db, flow_id=flow_id, force_refresh=force_refresh)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 404
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'Light-testing HTTP metadata probe failed: {exc}'}), 500

    @app.route('/api/flows/<int:flow_id>/probe/pcap-mimic', methods=['POST'])
    def api_flow_probe_pcap_mimic(flow_id: int):
        db = get_db()
        force_refresh = bool((request.get_json(silent=True) or {}).get('force_refresh'))
        try:
            result = run_pcap_mimic_request(db, flow_id=flow_id, force_refresh=force_refresh)
            db.commit()
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 404
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'PCAP-Mimic request failed: {exc}'}), 500

    @app.route('/api/flows/<int:flow_id>/enrich/shodan', methods=['POST'])
    def api_flow_enrich_shodan(flow_id: int):
        db = get_db()
        force_refresh = bool((request.get_json(silent=True) or {}).get('force_refresh'))
        try:
            result = enrich_flow_with_shodan(
                db,
                app.extensions['shodan_service'],
                flow_id=flow_id,
                force_refresh=force_refresh,
            )
            db.commit()
            return jsonify(result)
        except ShodanNotConfiguredError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 400
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 404
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'Shodan enrichment failed: {exc}'}), 500

    @app.route('/api/export', methods=['POST'])
    def api_export():
        payload = request.get_json(silent=True) or {}
        db = get_db()
        try:
            result = create_export(
                db,
                output_dir=app.config['OUTPUT_DIR'],
                scope=(payload.get('scope') or ''),
                export_format=(payload.get('format') or ''),
                flow_id=payload.get('flow_id'),
                search_value=payload.get('search_value'),
                search_type=payload.get('search_type'),
            )
            db.commit()
            result['download_url'] = f"/api/downloads/{result['filename']}"
            return jsonify(result)
        except ValueError as exc:
            db.rollback()
            return jsonify({'error': str(exc)}), 400
        except Exception as exc:
            db.rollback()
            return jsonify({'error': f'Export failed: {exc}'}), 500

    @app.route('/api/downloads/<path:filename>')
    def api_download(filename: str):
        return send_from_directory(app.config['OUTPUT_DIR'], filename, as_attachment=True)

    @app.route("/healthz")
    def healthz():
        db = get_db()
        db.execute("SELECT 1")
        return {
            "status": "ok",
            "shodan_enabled": app.config["SHODAN_ENABLED"],
        }

    return app
