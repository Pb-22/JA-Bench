#!/usr/bin/env python3
"""Clean browser top-sites PCAP/PCAPNG captures for JA-Bench.

The script preserves the raw file, builds a target-IP allowlist from capture sidecars
when available, writes a filtered PCAPNG, and emits a JSON/Markdown report.

Preferred sidecars from top-site-browser-pcap.ps1:
  - capture-filter.txt
  - resolved-targets.csv or resolved-targets*.csv
  - top-sites.csv
  - visit-log.csv
  - pcap-files.csv

Cleaning policy:
  - Always keep only TCP/80 and TCP/443.
  - If an allowlist is found, also require ip.addr to match one of the intended
    resolved target IPs.
  - If no allowlist is found, abort unless --allow-no-allowlist is passed.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])|(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])")
BAD_IP_TOKENS = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::", "::1"}
DEFAULT_OUTPUT_ROOT = Path.home() / "Documents" / "JA-Bench-PCAP-Cleaning"


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise RuntimeError(
            "Command failed:\n  " + " ".join(cmd) +
            f"\nexit={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"Missing required command: {name}. Install Wireshark/tshark first.")
    return path


def valid_ip(value: str) -> str | None:
    value = value.strip().strip('"').strip("'")
    if not value or value in BAD_IP_TOKENS:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    # Keep public and CDN IPs; reject local management/background ranges.
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        return None
    return str(ip)


def extract_ips_from_text(text: str) -> set[str]:
    ips: set[str] = set()
    for token in IP_RE.findall(text):
        ip = valid_ip(token)
        if ip:
            ips.add(ip)
    return ips


def read_csv_ips(path: Path) -> set[str]:
    ips: set[str] = set()
    try:
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            rows = list(csv.DictReader(f))
    except Exception:
        return ips
    for row in rows:
        for key, value in row.items():
            if value is None:
                continue
            lk = (key or "").lower()
            if lk in {"ip", "address", "resolved_ip", "target_ip"} or "ip" in lk:
                ip = valid_ip(str(value))
                if ip:
                    ips.add(ip)
            else:
                ips.update(extract_ips_from_text(str(value)))
    return ips


def candidate_sidecars(input_path: Path, explicit_dirs: Iterable[Path]) -> list[Path]:
    dirs = []
    for d in [input_path.parent, input_path.parent.parent, *explicit_dirs]:
        if d and d.exists() and d not in dirs:
            dirs.append(d)
    names = {
        "capture-filter.txt",
        "resolved-targets.csv",
        "top-sites.csv",
        "visit-log.csv",
        "pcap-files.csv",
    }
    found: list[Path] = []
    for d in dirs:
        for p in d.iterdir():
            if not p.is_file():
                continue
            low = p.name.lower()
            if low in names or low.startswith("resolved-target") or low.startswith("capture-filter"):
                found.append(p)
    return sorted(set(found))


def build_allowlist(input_path: Path, sidecar_dirs: Iterable[Path]) -> tuple[set[str], dict[str, list[str]]]:
    sources: dict[str, list[str]] = {}
    ips: set[str] = set()
    for p in candidate_sidecars(input_path, sidecar_dirs):
        found: set[str] = set()
        if p.suffix.lower() == ".csv":
            found |= read_csv_ips(p)
        else:
            try:
                found |= extract_ips_from_text(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
        if found:
            sources[str(p)] = sorted(found)
            ips |= found
    return ips, sources


def tshark_count(path: Path, display_filter: str | None = None) -> int:
    cmd = ["tshark", "-r", str(path)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-e", "frame.number"]
    proc = run(cmd)
    return sum(1 for line in proc.stdout.splitlines() if line.strip())


def field_inventory(path: Path, display_filter: str | None = None, limit: int = 50) -> dict[str, int]:
    cmd = ["tshark", "-r", str(path)]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-E", "separator=,"]
    proc = run(cmd)
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        parts = line.split(",")
        if len(parts) < 4:
            continue
        src, dst, sp, dp = parts[:4]
        key = f"{src}:{sp} -> {dst}:{dp}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit])


def make_display_filter(allow_ips: set[str], allow_no_allowlist: bool) -> str:
    port_part = "(tcp.port == 80 or tcp.port == 443)"
    if allow_ips:
        ip_part = " or ".join(f"ip.addr == {ip}" if ":" not in ip else f"ipv6.addr == {ip}" for ip in sorted(allow_ips))
        return f"{port_part} and ({ip_part})"
    if allow_no_allowlist:
        return port_part
    raise SystemExit(
        "No target-IP allowlist found from sidecars. Refusing to guess. "
        "Put capture-filter.txt or resolved-targets.csv beside the PCAP, "
        "or rerun with --allow-no-allowlist to keep only TCP/80 and TCP/443."
    )


def write_report(report_path: Path, data: dict) -> None:
    report_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = report_path.with_suffix(".md")
    md.write_text(
        "# JA-Bench PCAP cleaning report\n\n"
        f"- input: `{data['input']}`\n"
        f"- raw_copy: `{data['raw_copy']}`\n"
        f"- cleaned: `{data['cleaned']}`\n"
        f"- display_filter: `{data['display_filter']}`\n"
        f"- original_packets: {data['original_packets']}\n"
        f"- kept_packets: {data['kept_packets']}\n"
        f"- removed_packets: {data['removed_packets']}\n"
        f"- allowlist_ip_count: {len(data['allowlist_ips'])}\n\n"
        "## Allowlist sources\n\n"
        + "\n".join(f"- `{src}`: {len(ips)} IPs" for src, ips in data["allowlist_sources"].items())
        + "\n\n## Top cleaned conversations\n\n"
        + "\n".join(f"- {count} `{conv}`" for conv, count in data["top_cleaned_conversations"].items())
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Clean a JA-Bench browser top-sites PCAP/PCAPNG capture.")
    ap.add_argument("pcap", type=Path, help="Input .pcap or .pcapng")
    ap.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    ap.add_argument("--sidecar-dir", type=Path, action="append", default=[])
    ap.add_argument("--allow-no-allowlist", action="store_true", help="If no sidecar allowlist exists, keep only TCP/80 and TCP/443.")
    ap.add_argument("--force", action="store_true", help="Overwrite existing cleaned output/report.")
    args = ap.parse_args()

    require_tool("tshark")
    input_path = args.pcap.expanduser().resolve()
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_root.expanduser().resolve() / stamp
    raw_dir = run_dir / "raw"
    cleaned_dir = run_dir / "cleaned"
    report_dir = run_dir / "reports"
    for d in (raw_dir, cleaned_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)

    raw_copy = raw_dir / input_path.name
    if raw_copy.exists() and not args.force:
        raise SystemExit(f"Raw copy already exists: {raw_copy}; pass --force to overwrite.")
    shutil.copy2(input_path, raw_copy)

    allow_ips, allow_sources = build_allowlist(input_path, args.sidecar_dir)
    display_filter = make_display_filter(allow_ips, args.allow_no_allowlist)

    cleaned_path = cleaned_dir / (input_path.stem + ".cleaned.pcapng")
    if cleaned_path.exists() and not args.force:
        raise SystemExit(f"Cleaned output already exists: {cleaned_path}; pass --force to overwrite.")

    original_packets = tshark_count(raw_copy)
    run(["tshark", "-r", str(raw_copy), "-Y", display_filter, "-w", str(cleaned_path)])
    kept_packets = tshark_count(cleaned_path)

    report = {
        "created_utc": stamp,
        "input": str(input_path),
        "raw_copy": str(raw_copy),
        "cleaned": str(cleaned_path),
        "display_filter": display_filter,
        "original_packets": original_packets,
        "kept_packets": kept_packets,
        "removed_packets": original_packets - kept_packets,
        "allowlist_ips": sorted(allow_ips),
        "allowlist_sources": allow_sources,
        "top_original_conversations": field_inventory(raw_copy),
        "top_cleaned_conversations": field_inventory(cleaned_path) if kept_packets else {},
    }
    report_path = report_dir / (input_path.stem + ".cleaning-report.json")
    write_report(report_path, report)

    print(f"raw_copy={raw_copy}")
    print(f"cleaned={cleaned_path}")
    print(f"report_json={report_path}")
    print(f"report_md={report_path.with_suffix('.md')}")
    print(f"original_packets={original_packets}")
    print(f"kept_packets={kept_packets}")
    print(f"removed_packets={original_packets - kept_packets}")
    if not allow_ips:
        print("warning=no_sidecar_allowlist_used_tcp_80_443_only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
