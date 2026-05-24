from __future__ import annotations

import os
from pathlib import Path


class Config:
    DATA_ROOT = Path(os.environ.get("JA_BENCH_DATA_ROOT", "/data"))
    DB_PATH = Path(os.environ.get("JA_BENCH_DB_PATH", str(DATA_ROOT / "db" / "ja-bench.sqlite3")))
    UPLOAD_DIR = DATA_ROOT / "uploads"
    OUTPUT_DIR = DATA_ROOT / "output"
    CACHE_DIR = DATA_ROOT / "cache"
    CONFIG_DIR = DATA_ROOT / "config"
    MAX_CONTENT_LENGTH = 512 * 1024 * 1024
    SECRET_KEY = os.environ.get("JA_BENCH_SECRET_KEY", "ja-bench-dev-secret")
    SHODAN_ENABLED = bool(os.environ.get("SHODAN_API_KEY"))
    SHODAN_CACHE_TTL_SECONDS = int(os.environ.get("SHODAN_CACHE_TTL_SECONDS", "86400"))
