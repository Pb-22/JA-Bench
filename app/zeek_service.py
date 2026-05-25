from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_zeek_capture(pcap_path: Path, output_root: Path, script_path: Path) -> dict[str, Any]:
    sample_dir = output_root / pcap_path.stem
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["zeek", "-Cr", str(pcap_path), str(script_path)]
    proc = subprocess.run(
        cmd,
        cwd=sample_dir,
        capture_output=True,
        text=True,
        check=False,
    )

    logs = {}
    for log_path in sorted(sample_dir.glob("*.log")):
        try:
            line_count = sum(1 for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())
        except OSError:
            line_count = 0
        logs[log_path.name] = {
            "path": str(log_path),
            "line_count": line_count,
        }

    result = {
        "status": "ok" if proc.returncode == 0 else "error",
        "command": cmd,
        "stdout_tail": proc.stdout[-4000:] if proc.stdout else "",
        "stderr_tail": proc.stderr[-4000:] if proc.stderr else "",
        "logs": logs,
    }

    for preferred in ("ssl.log", "http.log", "conn.log", "ja4ssh.log", "ja4d.log", "x509.log"):
        if preferred in logs:
            result.setdefault("highlights", []).append(
                {"log": preferred, "line_count": logs[preferred]["line_count"]}
            )
    return result
