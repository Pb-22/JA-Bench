#!/usr/bin/env python3
"""macOS top-site browser PCAP collector for JA-Bench.

Captures one PCAPNG per browser for Chrome/Safari/Edge while constraining
capture to TCP/80+443 and pre-resolved target IPs. The workflow mirrors the
Windows and Ubuntu collectors: deterministic rank order, bare+www DNS
resolution, target-IP BPF allowlisting, one capture per browser, and sidecars
for later fingerprint/cleaning analysis.

Examples:
  python3 top_site_browser_pcap_macos.py --list-interfaces
  sudo python3 top_site_browser_pcap_macos.py --browser All --start-rank 1 --count 20 --interface en0 --fresh-run
  sudo python3 top_site_browser_pcap_macos.py --browser Safari --start-rank 1 --count 20 --interface en0 --fresh-run

Notes:
  - dumpcap on macOS usually requires root/sudo or Wireshark capture-helper setup.
  - Chrome and Edge are launched with temporary user-data dirs and background/
    QUIC-disabling flags where supported.
  - Safari does not provide a stable per-run profile CLI. This script opens URLs
    with Safari, asks Safari to quit between visits via AppleScript, and records
    the limitation in run metadata.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable, Mapping, Sequence

TRANC0_URL = "https://tranco-list.eu/top-1m.csv.zip"
DEFAULT_OUTPUT = Path.home() / "Desktop" / "TopSitesPcap"


def run(cmd: Sequence[str], *, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), text=True, capture_output=True, check=check, timeout=timeout)


def find_program(candidates: Sequence[str]) -> str | None:
    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser()
        if p.exists() and os.access(p, os.X_OK):
            return str(p)
        found = shutil.which(c)
        if found:
            return found
    return None


def safe_token(value: str | None) -> str:
    if not value:
        return "unknown"
    token = re.sub(r"[\s/:*?\"<>|\\]+", "_", value.strip())
    token = re.sub(r"[^A-Za-z0-9._-]", "_", token)
    token = re.sub(r"_+", "_", token).strip("_.-")
    return token or "unknown"


def write_csv(path: Path, rows: Iterable[Mapping[str, object]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_os_token() -> str:
    try:
        product = run(["sw_vers", "-productName"], check=False).stdout.strip() or "macOS"
        version = run(["sw_vers", "-productVersion"], check=False).stdout.strip() or "unknown_version"
        build = run(["sw_vers", "-buildVersion"], check=False).stdout.strip() or "unknown_build"
        arch = run(["uname", "-m"], check=False).stdout.strip() or "unknown_arch"
        return safe_token(f"{product}_{version}_build_{build}_{arch}")
    except Exception:
        return safe_token(sys.platform)


def bundle_version(app_path: Path, exe_path: str, browser_name: str) -> str:
    version = ""
    # mdls works on .app bundles when Spotlight metadata is present.
    try:
        cp = run(["mdls", "-name", "kMDItemVersion", "-raw", str(app_path)], check=False, timeout=10)
        v = cp.stdout.strip()
        if v and v != "(null)":
            version = v
    except Exception:
        pass
    if not version:
        plist = app_path / "Contents" / "Info.plist"
        try:
            cp = run(["/usr/bin/defaults", "read", str(plist.with_suffix("")), "CFBundleShortVersionString"], check=False, timeout=10)
            version = cp.stdout.strip()
        except Exception:
            pass
    if not version:
        try:
            cp = run([exe_path, "--version"], check=False, timeout=10)
            version = (cp.stdout or cp.stderr).strip().splitlines()[0]
            version = version.replace(browser_name, "").strip()
        except Exception:
            pass
    return safe_token(f"{browser_name}_{version or 'unknown_version'}")


def discover_browsers(selection: str, allow_missing: bool = False) -> list[dict[str, str]]:
    defs = {
        "Chrome": [
            (Path("/Applications/Google Chrome.app"), "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            (Path.home() / "Applications" / "Google Chrome.app", str(Path.home() / "Applications" / "Google Chrome.app" / "Contents" / "MacOS" / "Google Chrome")),
        ],
        "Safari": [
            (Path("/Applications/Safari.app"), "/Applications/Safari.app/Contents/MacOS/Safari"),
            (Path("/System/Applications/Safari.app"), "/System/Applications/Safari.app/Contents/MacOS/Safari"),
        ],
        "Edge": [
            (Path("/Applications/Microsoft Edge.app"), "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            (Path.home() / "Applications" / "Microsoft Edge.app", str(Path.home() / "Applications" / "Microsoft Edge.app" / "Contents" / "MacOS" / "Microsoft Edge")),
        ],
    }
    wanted = list(defs) if selection == "All" else [selection]
    browsers: list[dict[str, str]] = []
    missing: list[str] = []
    for name in wanted:
        chosen: tuple[Path, str] | None = None
        for app, exe in defs[name]:
            if app.exists() and Path(exe).exists() and os.access(exe, os.X_OK):
                chosen = (app, exe)
                break
        if not chosen:
            missing.append(name)
            continue
        browsers.append({"name": name, "app_path": str(chosen[0]), "path": chosen[1]})
    if missing and not allow_missing:
        raise SystemExit("Selected browser(s) not found: " + ", ".join(missing) + ". Use --allow-missing-browsers to skip them.")
    return browsers


def list_interfaces(dumpcap: str) -> None:
    cp = run([dumpcap, "-D"], check=False)
    sys.stdout.write(cp.stdout)
    if cp.stderr:
        sys.stderr.write(cp.stderr)


def download_tranco(url: str, tmp_dir: Path) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    zip_path = tmp_dir / "top-1m.csv.zip"
    urllib.request.urlretrieve(url, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(tmp_dir)
    csv_path = tmp_dir / "top-1m.csv"
    if not csv_path.exists():
        raise RuntimeError(f"Expected {csv_path} after extracting Tranco ZIP")
    return csv_path


def load_sites(csv_path: Path, start_rank: int, count: int) -> list[tuple[int, str]]:
    end_rank = start_rank + count - 1
    rows: list[tuple[int, str]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for rank_s, domain, *_ in reader:
            rank = int(rank_s)
            if rank < start_rank:
                continue
            if rank > end_rank:
                break
            rows.append((rank, domain.strip().lower()))
    if len(rows) != count:
        raise RuntimeError(f"Expected {count} sites for ranks {start_rank}-{end_rank}, got {len(rows)}")
    return rows


def load_sites_from_run(run_dir: Path) -> list[tuple[int, str]]:
    rows = read_csv(run_dir / "top-sites.csv")
    return [(int(r["rank"]), r["domain"]) for r in rows]


def load_target_ips_from_run(run_dir: Path) -> list[str]:
    rows = read_csv(run_dir / "resolved-target-ips.csv")
    return sorted({r["ip"] for r in rows if r.get("ip") and r.get("ip") != "RESOLUTION_FAILED"})


def resolve_site_ips(sites: Sequence[tuple[int, str]]) -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    ips: set[str] = set()
    for rank, domain in sites:
        names = [domain]
        if not domain.startswith("www."):
            names.append(f"www.{domain}")
        for name in names:
            answered = False
            try:
                infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                infos = []
            for family, _socktype, _proto, _canon, sockaddr in infos:
                ip = str(sockaddr[0])
                record_type = "AAAA" if family == socket.AF_INET6 else "A"
                if (name, ip) not in {(r.get("resolved_name"), r.get("ip")) for r in rows}:
                    rows.append({"rank": str(rank), "site_domain": domain, "resolved_name": name, "record_type": record_type, "ip": ip})
                ips.add(ip)
                answered = True
            if not answered:
                rows.append({"rank": str(rank), "site_domain": domain, "resolved_name": name, "record_type": "A/AAAA", "ip": "RESOLUTION_FAILED"})
    return rows, sorted(ips)


def build_capture_filter(ips: Sequence[str]) -> str:
    if not ips:
        raise RuntimeError("No target IPs resolved; refusing to capture broad traffic")
    return "tcp and (port 80 or port 443) and (" + " or ".join(f"host {ip}" for ip in sorted(ips)) + ")"


def newest_reusable_run(output_dir: Path, range_token: str) -> Path | None:
    candidates = sorted(output_dir.glob(f"top-sites-{range_token}-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in candidates:
        if (p / "top-sites.csv").exists() and (p / "resolved-target-ips.csv").exists() and (p / "capture-filter.txt").exists():
            return p
    return None


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def terminate_process_group(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass


def quit_safari() -> None:
    # AppleScript gracefully asks Safari to quit. Ignore failures on non-GUI shells.
    subprocess.run(["/usr/bin/osascript", "-e", 'tell application "Safari" to quit'], text=True, capture_output=True, check=False, timeout=10)
    time.sleep(1)
    subprocess.run(["/usr/bin/pkill", "-x", "Safari"], text=True, capture_output=True, check=False, timeout=10)


def browser_args(browser: dict[str, str], url: str, profile_dir: Path) -> list[str]:
    name = browser["name"]
    if name in {"Chrome", "Edge"}:
        return [
            browser["path"],
            f"--user-data-dir={profile_dir}",
            "--new-window",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-extensions",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-quic",
            "--disable-features=UseDnsHttpsSvcbAlpn,EncryptedClientHello",
            url,
        ]
    if name == "Safari":
        # Use /usr/bin/open so macOS routes the URL through the app bundle cleanly.
        return ["/usr/bin/open", "-a", browser["app_path"], url]
    raise ValueError(name)


def visit_url(browser: dict[str, str], url: str, profile_root: Path, seconds: int, between_seconds: int, log_dir: Path) -> None:
    profile_dir = profile_root / safe_token(url)
    if browser["name"] != "Safari":
        clean_dir(profile_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{browser['name']}-{safe_token(url)}.browser.log"
    if browser["name"] == "Safari":
        quit_safari()
    args = browser_args(browser, url, profile_dir)
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, text=True)
        try:
            if browser["name"] == "Safari":
                # open(1) exits quickly; keep Safari alive for the page dwell time.
                proc.wait(timeout=10)
                time.sleep(seconds)
            else:
                time.sleep(seconds)
        finally:
            if browser["name"] == "Safari":
                quit_safari()
            else:
                terminate_process_group(proc)
    time.sleep(between_seconds)


def start_capture(dumpcap: str, interface: str, capture_filter: str, pcap_path: Path, log_path: Path) -> subprocess.Popen[str]:
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen([dumpcap, "-i", interface, "-f", capture_filter, "-w", str(pcap_path)], stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    time.sleep(4)
    if proc.poll() is not None:
        log.close()
        err = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        raise RuntimeError(f"dumpcap exited early for {pcap_path}\n{err}")
    proc._ja_bench_log_handle = log  # type: ignore[attr-defined]
    return proc


def stop_capture(proc: subprocess.Popen[str] | None) -> None:
    if not proc:
        return
    if proc.poll() is None:
        terminate_process_group(proc)
    log = getattr(proc, "_ja_bench_log_handle", None)
    if log:
        log.close()


def is_browser_complete(browser_name: str, expected_visits: int, visit_rows: list[dict[str, str]], pcap_rows: list[dict[str, str]]) -> bool:
    visits = [r for r in visit_rows if r.get("browser") == browser_name]
    manifests = [r for r in pcap_rows if r.get("browser") == browser_name]
    if len(visits) < expected_visits or not manifests:
        return False
    for row in manifests:
        p = Path(row.get("pcap_path", ""))
        if row.get("completed") == "true" and p.exists() and p.stat().st_size > 0:
            return True
    return False


def remove_browser_state(browser_name: str, visit_rows: list[dict[str, str]], pcap_rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    for row in pcap_rows:
        if row.get("browser") == browser_name:
            for key in ("pcap_path", "dumpcap_log"):
                p = Path(row.get(key, ""))
                if p.exists():
                    p.unlink()
    return [r for r in visit_rows if r.get("browser") != browser_name], [r for r in pcap_rows if r.get("browser") != browser_name]


def main() -> int:
    parser = argparse.ArgumentParser(description="macOS Chrome/Safari/Edge top-site PCAP collector for JA-Bench")
    parser.add_argument("--browser", choices=["Chrome", "Safari", "Edge", "All"], default="All")
    parser.add_argument("--start-rank", type=int, default=1)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fresh-run", action="store_true")
    parser.add_argument("--page-seconds", type=int, default=12)
    parser.add_argument("--between-seconds", type=int, default=2)
    parser.add_argument("--tranco-url", default=TRANC0_URL)
    parser.add_argument("--allow-missing-browsers", action="store_true")
    parser.add_argument("--overwrite-browser", action="append", choices=["Chrome", "Safari", "Edge"], default=[])
    parser.add_argument("--dry-run", action="store_true", help="Resolve targets and write sidecars, but do not capture or launch browsers")
    args = parser.parse_args()

    if args.start_rank < 1 or args.count < 1:
        raise SystemExit("--start-rank and --count must be positive")

    dumpcap = find_program(["/Applications/Wireshark.app/Contents/MacOS/dumpcap", "/usr/local/bin/dumpcap", "/opt/homebrew/bin/dumpcap", "dumpcap"])
    if not dumpcap:
        raise SystemExit("dumpcap not found. Install Wireshark or make dumpcap available on PATH.")
    if args.list_interfaces:
        list_interfaces(dumpcap)
        return 0

    browsers = discover_browsers(args.browser, allow_missing=args.allow_missing_browsers)
    if not browsers:
        raise SystemExit("No selected browsers are installed/found.")

    range_token = f"{args.start_rank}-{args.start_rank + args.count - 1}"
    args.output_dir.mkdir(parents=True, exist_ok=True)

    reusable = None if args.fresh_run else newest_reusable_run(args.output_dir, range_token)
    if reusable:
        run_dir = reusable
        print(f"Resuming existing run directory: {run_dir}")
        sites = load_sites_from_run(run_dir)
        target_ips = load_target_ips_from_run(run_dir)
        capture_filter = (run_dir / "capture-filter.txt").read_text(encoding="utf-8").strip()
    else:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        run_dir = args.output_dir / f"top-sites-{range_token}-{stamp}"
        run_dir.mkdir(parents=True, exist_ok=False)
        tmp = run_dir / "tmp"
        print("Downloading Tranco list...")
        tranco_csv = download_tranco(args.tranco_url, tmp)
        sites = load_sites(tranco_csv, args.start_rank, args.count)
        write_csv(run_dir / "top-sites.csv", [{"rank": rank, "domain": domain} for rank, domain in sites], ["rank", "domain"])
        print(f"Resolving rank {range_token} target IPs...")
        resolved_rows, target_ips = resolve_site_ips(sites)
        write_csv(run_dir / "resolved-target-ips.csv", resolved_rows, ["rank", "site_domain", "resolved_name", "record_type", "ip"])
        capture_filter = build_capture_filter(target_ips)
        (run_dir / "capture-filter.txt").write_text(capture_filter + "\n", encoding="ascii")

    profiles_root = run_dir / "browser-profiles"
    profiles_root.mkdir(parents=True, exist_ok=True)
    logs_root = run_dir / "browser-logs"
    logs_root.mkdir(exist_ok=True)
    os_token = get_os_token()
    expected_visits = len(sites) * 2

    metadata_rows = []
    for b in browsers:
        version_token = bundle_version(Path(b["app_path"]), b["path"], b["name"])
        metadata_rows.append({
            "os_version_token": os_token,
            "browser": b["name"],
            "browser_app_path": b["app_path"],
            "browser_path": b["path"],
            "browser_version_token": version_token,
            "site_range": range_token,
            "capture_interface": args.interface,
            "capture_filter": capture_filter,
            "profile_note": "Safari uses existing app profile; Chrome/Edge use temporary user-data dirs" if b["name"] == "Safari" else "temporary user-data dir per visit",
        })
    write_csv(run_dir / "run-metadata.csv", metadata_rows, ["os_version_token", "browser", "browser_app_path", "browser_path", "browser_version_token", "site_range", "capture_interface", "capture_filter", "profile_note"])

    visit_path = run_dir / "visit-log.csv"
    manifest_path = run_dir / "pcap-files.csv"
    visit_rows = read_csv(visit_path)
    pcap_rows = read_csv(manifest_path)

    print(f"Output directory: {run_dir}")
    print(f"Capture filter: {run_dir / 'capture-filter.txt'}")
    print("Browsers: " + ", ".join(b["name"] for b in browsers))
    if args.dry_run:
        print("Dry run requested; sidecars written, no capture/browser launch performed.")
        return 0

    for b in browsers:
        name = b["name"]
        if name in args.overwrite_browser:
            print(f"Overwriting browser state for {name}")
            visit_rows, pcap_rows = remove_browser_state(name, visit_rows, pcap_rows)
        if is_browser_complete(name, expected_visits, visit_rows, pcap_rows):
            print(f"Skipping complete browser: {name}")
            continue
        if any(r.get("browser") == name for r in visit_rows) or any(r.get("browser") == name for r in pcap_rows):
            print(f"Restarting incomplete browser from scratch: {name}")
            visit_rows, pcap_rows = remove_browser_state(name, visit_rows, pcap_rows)

        version_token = bundle_version(Path(b["app_path"]), b["path"], name)
        file_base = f"{os_token}_{version_token}_{range_token}"
        pcap_path = run_dir / f"{file_base}.pcapng"
        dumpcap_log = run_dir / f"{file_base}.dumpcap.log"
        profile_root = profiles_root / name
        profile_root.mkdir(parents=True, exist_ok=True)

        print(f"Starting capture for {name} on interface {args.interface}")
        cap = None
        start_utc = utc_now()
        try:
            cap = start_capture(dumpcap, args.interface, capture_filter, pcap_path, dumpcap_log)
            pcap_rows.append({"browser": name, "pcap_path": str(pcap_path), "dumpcap_log": str(dumpcap_log), "browser_version_token": version_token, "site_range": range_token, "start_utc": start_utc, "end_utc": "", "completed": "false"})
            write_csv(manifest_path, pcap_rows, ["browser", "pcap_path", "dumpcap_log", "browser_version_token", "site_range", "start_utc", "end_utc", "completed"])
            for rank, domain in sites:
                for scheme in ("http", "https"):
                    url = f"{scheme}://{domain}/"
                    started = utc_now()
                    print(f"{name} rank {rank}: {url}")
                    visit_url(b, url, profile_root, args.page_seconds, args.between_seconds, logs_root)
                    ended = utc_now()
                    visit_rows.append({"browser": name, "rank": str(rank), "domain": domain, "scheme": scheme, "url": url, "pcap_path": str(pcap_path), "start_utc": started, "end_utc": ended})
                    write_csv(visit_path, visit_rows, ["browser", "rank", "domain", "scheme", "url", "pcap_path", "start_utc", "end_utc"])
        finally:
            print(f"Stopping capture for {name}...")
            stop_capture(cap)
            if name == "Safari":
                quit_safari()
        end_utc = utc_now()
        for row in pcap_rows:
            if row.get("browser") == name and row.get("pcap_path") == str(pcap_path):
                row["end_utc"] = end_utc
                row["completed"] = "true"
        write_csv(manifest_path, pcap_rows, ["browser", "pcap_path", "dumpcap_log", "browser_version_token", "site_range", "start_utc", "end_utc", "completed"])

    print(f"Done. Output directory: {run_dir}")
    print(f"PCAP manifest: {manifest_path}")
    print(f"Visit log: {visit_path}")
    print(f"Resolved IPs: {run_dir / 'resolved-target-ips.csv'}")
    print(f"Capture filter: {run_dir / 'capture-filter.txt'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
