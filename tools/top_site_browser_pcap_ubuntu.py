#!/usr/bin/env python3
"""Ubuntu top-site browser PCAP collector for JA-Bench.

Captures one PCAPNG per browser for Chrome/Chromium/Firefox while constraining
capture to TCP/80+443 and pre-resolved target IPs. The workflow mirrors lessons
from the Windows PowerShell collector: deterministic rank order, bare+www DNS
resolution, target-IP BPF allowlisting, fresh browser profiles, HTTP/3/QUIC
suppression, sidecar manifests, and browser-granularity resume.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
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
DEFAULT_OUTPUT = Path.home() / "Documents" / "Pcap_check" / "ubuntu-top-sites"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_token(value: str) -> str:
    value = (value or "unknown").strip()
    value = re.sub(r"[\\/:*?\"<>|\s]+", "_", value)
    value = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_.-")
    return value or "unknown"


def run(cmd: list[str], *, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc


def find_program(candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        p = shutil.which(candidate)
        if p:
            return p
        if Path(candidate).exists():
            return str(Path(candidate).resolve())
    return None


def get_os_token() -> str:
    pretty = "Ubuntu"
    version = "unknown"
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            data = {}
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    data[k] = v.strip('"')
            pretty = data.get("PRETTY_NAME") or data.get("NAME") or pretty
            version = data.get("VERSION_ID") or version
    except OSError:
        pass
    arch = run(["uname", "-m"], check=False).stdout.strip() or "unknown_arch"
    return safe_token(f"{pretty}_{version}_{arch}")


def browser_version_token(name: str, path: str) -> str:
    proc = run([path, "--version"], check=False, timeout=20)
    text = (proc.stdout or proc.stderr or "").strip().splitlines()[0:1]
    version_text = text[0] if text else f"{name} unknown_version"
    return safe_token(version_text)


def discover_browsers(selection: str, allow_missing: bool = False) -> list[dict[str, str]]:
    defs = {
        # Prefer explicit system paths before PATH lookup so local Playwright/Chrome-for-Testing shims
        # do not accidentally stand in for the distro browser being measured.
        "Chrome": ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "google-chrome-stable", "google-chrome"],
        "Chromium": ["/usr/bin/chromium-browser", "/usr/bin/chromium", "chromium-browser", "chromium", str(Path.home() / ".local/bin/chromium")],
        # Prefer the real Firefox binary inside the snap over /usr/bin/firefox.
        # The snap launcher can start but fail to emit host-visible target traffic
        # in headless captures; executing the bundled binary directly preserves the
        # same Firefox build while avoiding snap confinement wrappers.
        "Firefox": ["/snap/firefox/current/usr/lib/firefox/firefox", "/usr/bin/firefox", "/usr/local/bin/firefox", "firefox"],
    }
    wanted = list(defs) if selection == "All" else [selection]
    browsers: list[dict[str, str]] = []
    missing: list[str] = []
    for name in wanted:
        path = find_program(defs[name])
        if path:
            browsers.append({"name": name, "path": path})
        else:
            missing.append(name)
    if missing and not allow_missing:
        raise RuntimeError(f"Selected browser(s) not found: {', '.join(missing)}. Install them or use --allow-missing-browsers.")
    return browsers


def list_interfaces(dumpcap: str) -> None:
    proc = run([dumpcap, "-D"], check=False)
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def download_tranco(url: str, tmp_dir: Path) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    zip_path = tmp_dir / "top-1m.csv.zip"
    urllib.request.urlretrieve(url, zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmp_dir)
    csv_path = tmp_dir / "top-1m.csv"
    if not csv_path.exists():
        raise RuntimeError(f"expected {csv_path} after extracting Tranco ZIP")
    return csv_path


def load_sites(csv_path: Path, start_rank: int, count: int) -> list[tuple[int, str]]:
    end_rank = start_rank + count - 1
    sites: list[tuple[int, str]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            if start_rank <= rank <= end_rank:
                if len(row) < 2:
                    continue
                sites.append((rank, row[1].strip().lower()))
            if rank >= end_rank:
                break
    if len(sites) != count:
        raise RuntimeError(f"expected {count} sites for ranks {start_rank}-{end_rank}, got {len(sites)}")
    return sites


def write_csv(path: Path, rows: Sequence[Mapping[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def resolve_site_ips(sites: list[tuple[int, str]]) -> tuple[list[dict[str, object]], list[str]]:
    rows: list[dict[str, object]] = []
    ips: set[str] = set()
    for rank, domain in sites:
        names = [domain]
        if not domain.startswith("www."):
            names.append(f"www.{domain}")
        for name in names:
            answered = False
            try:
                infos = socket.getaddrinfo(name, 0, type=socket.SOCK_STREAM)
            except socket.gaierror:
                infos = []
            for family, _socktype, _proto, _canon, sockaddr in infos:
                ip = str(sockaddr[0])
                if not ip:
                    continue
                answered = True
                record_type = "AAAA" if family == socket.AF_INET6 else "A"
                ips.add(ip)
                rows.append({"rank": rank, "site_domain": domain, "resolved_name": name, "record_type": record_type, "ip": ip})
            if not answered:
                rows.append({"rank": rank, "site_domain": domain, "resolved_name": name, "record_type": "A/AAAA", "ip": "RESOLUTION_FAILED"})
    return rows, sorted(ips)


def build_capture_filter(ips: list[str]) -> str:
    if not ips:
        raise RuntimeError("No target IPs resolved; refusing to capture broad traffic.")
    terms = [f"host {ip}" for ip in ips]
    return "tcp and (port 80 or port 443) and (" + " or ".join(terms) + ")"


def newest_reusable_run(output_dir: Path, range_token: str) -> Path | None:
    if not output_dir.exists():
        return None
    candidates = sorted(output_dir.glob(f"top-sites-{range_token}-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for c in candidates:
        if (c / "top-sites.csv").exists() and (c / "capture-filter.txt").exists():
            return c
    return None


def load_sites_from_run(run_dir: Path) -> list[tuple[int, str]]:
    rows = read_csv(run_dir / "top-sites.csv")
    return [(int(r["rank"]), r["domain"].strip().lower()) for r in rows]


def load_target_ips_from_run(run_dir: Path) -> list[str]:
    rows = read_csv(run_dir / "resolved-target-ips.csv")
    ips: set[str] = set()
    for row in rows:
        value = (row.get("ip") or "").strip()
        if not value or value == "RESOLUTION_FAILED":
            continue
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return sorted(ips)


def firefox_prefs(profile_dir: Path) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    prefs = """user_pref(\"browser.shell.checkDefaultBrowser\", false);
user_pref(\"browser.startup.homepage\", \"about:blank\");
user_pref(\"browser.startup.page\", 0);
user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");
user_pref(\"browser.aboutwelcome.enabled\", false);
user_pref(\"startup.homepage_welcome_url\", \"\");
user_pref(\"startup.homepage_welcome_url.additional\", \"\");
user_pref(\"trailhead.firstrun.didSeeAboutWelcome\", true);
user_pref(\"browser.newtabpage.enabled\", false);
user_pref(\"browser.tabs.warnOnClose\", false);
user_pref(\"browser.warnOnQuit\", false);
user_pref(\"datareporting.healthreport.uploadEnabled\", false);
user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);
user_pref(\"network.http.http3.enabled\", false);
user_pref(\"toolkit.telemetry.enabled\", false);
user_pref(\"toolkit.telemetry.unified\", false);
user_pref(\"extensions.update.enabled\", false);
user_pref(\"app.update.enabled\", false);
user_pref(\"app.normandy.enabled\", false);
user_pref(\"app.shield.optoutstudies.enabled\", false);
user_pref(\"browser.safebrowsing.malware.enabled\", false);
user_pref(\"browser.safebrowsing.phishing.enabled\", false);
"""
    (profile_dir / "user.js").write_text(prefs, encoding="ascii")


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def browser_args(browser: dict[str, str], url: str, profile_dir: Path, headless: bool = False) -> list[str]:
    name = browser["name"]
    if name in {"Chrome", "Chromium"}:
        args = [
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
        if os.geteuid() == 0 or headless:
            args.insert(1, "--no-sandbox")
        if headless:
            args.insert(1, "--headless=new")
        return args
    if name == "Firefox":
        firefox_prefs(profile_dir)
        args = [browser["path"], "-no-remote", "-profile", str(profile_dir), "-new-window", url]
        if headless:
            args.insert(1, "--headless")
        return args
    raise ValueError(name)


def terminate_tree(proc: subprocess.Popen[str]) -> None:
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


def close_target_connections(target_ips: Sequence[str], settle_seconds: float = 2.0) -> None:
    """Force-close leftover TCP sockets to capture targets after each visit.

    Browsers can keep TCP sockets open through helper processes or leave the host
    with enough lingering connections to stress long top-site runs. Linux `ss -K`
    sends TCP RSTs for matching sockets; restricting matches to the pre-resolved
    capture target IPs and ports 80/443 avoids broad connection killing.
    """
    ss = find_program(["ss"])
    if not ss or not target_ips:
        time.sleep(settle_seconds)
        return
    for ip in target_ips:
        for port in ("80", "443"):
            run([ss, "-K", "dst", ip, "dport", "=", f":{port}"], check=False, timeout=5)
    time.sleep(settle_seconds)


def visit_url(browser: dict[str, str], url: str, profile_root: Path, seconds: int, between_seconds: int, headless: bool, log_dir: Path) -> None:
    profile_dir = profile_root / safe_token(url)
    clean_dir(profile_dir)
    args = browser_args(browser, url, profile_dir, headless=headless)
    # Recreate the log directory for each visit. The run directory may be cleaned
    # externally while a long capture is in progress; without this guard, the
    # capture can fail late with FileNotFoundError after most visits are done.
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{browser['name']}-{safe_token(url)}.browser.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, text=True)
        try:
            time.sleep(seconds)
        finally:
            terminate_tree(proc)
    time.sleep(between_seconds)


def start_capture(dumpcap: str, interface: str, capture_filter: str, pcap_path: Path, log_path: Path) -> subprocess.Popen[str]:
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen([dumpcap, "-i", interface, "-f", capture_filter, "-w", str(pcap_path)], stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    time.sleep(3)
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
        terminate_tree(proc)
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
        if p.exists() and p.stat().st_size > 0:
            return True
        if row.get("completed") == "true":
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
    parser = argparse.ArgumentParser(description="Ubuntu Chrome/Chromium/Firefox top-site PCAP collector for JA-Bench")
    parser.add_argument("--browser", choices=["Chrome", "Chromium", "Firefox", "All"], default="All")
    parser.add_argument("--start-rank", type=int, default=1)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--interface", default="any")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fresh-run", action="store_true")
    parser.add_argument("--page-seconds", type=int, default=12)
    parser.add_argument("--between-seconds", type=int, default=2)
    parser.add_argument("--tranco-url", default=TRANC0_URL)
    parser.add_argument("--allow-missing-browsers", action="store_true")
    parser.add_argument("--overwrite-browser", action="append", choices=["Chrome", "Chromium", "Firefox"], default=[])
    parser.add_argument("--headless", action="store_true", help="Launch browsers in headless mode where supported; useful on servers without X")
    parser.add_argument("--no-close-target-connections", action="store_true", help="Do not run ss -K to close TCP/80+443 sockets to resolved target IPs after each visit")
    parser.add_argument("--connection-settle-seconds", type=float, default=2.0, help="Seconds to wait after closing target sockets between visits")
    parser.add_argument("--dry-run", action="store_true", help="Resolve targets and write sidecars, but do not capture or launch browsers")
    args = parser.parse_args()

    if args.start_rank < 1 or args.count < 1:
        raise SystemExit("--start-rank and --count must be positive")

    dumpcap = find_program(["dumpcap"])
    if not dumpcap:
        raise SystemExit("dumpcap not found. Install tshark/wireshark first.")
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
        site_rows = [{"rank": rank, "domain": domain} for rank, domain in sites]
        write_csv(run_dir / "top-sites.csv", site_rows, ["rank", "domain"])
        print(f"Resolving rank {range_token} target IPs...")
        resolved_rows, target_ips = resolve_site_ips(sites)
        write_csv(run_dir / "resolved-target-ips.csv", resolved_rows, ["rank", "site_domain", "resolved_name", "record_type", "ip"])
        capture_filter = build_capture_filter(target_ips)
        (run_dir / "capture-filter.txt").write_text(capture_filter + "\n", encoding="ascii")

    # Browser snaps cannot reliably access hidden project paths such as
    # /home/claw/.openclaw/... for profile state. Keep browser profiles in /tmp
    # while leaving PCAPNGs and sidecars in the requested output directory.
    profiles_root = Path("/tmp/ja-bench-browser-profiles") / run_dir.name
    profiles_root.mkdir(parents=True, exist_ok=True)
    logs_root = run_dir / "browser-logs"
    logs_root.mkdir(exist_ok=True)
    os_token = get_os_token()
    expected_visits = len(sites) * 2

    metadata_rows = []
    for b in browsers:
        metadata_rows.append({
            "os_version_token": os_token,
            "browser": b["name"],
            "browser_path": b["path"],
            "browser_version_token": browser_version_token(b["name"], b["path"]),
            "site_range": range_token,
            "capture_interface": args.interface,
            "capture_filter": capture_filter,
            "headless": str(args.headless).lower(),
        })
    write_csv(run_dir / "run-metadata.csv", metadata_rows, ["os_version_token", "browser", "browser_path", "browser_version_token", "site_range", "capture_interface", "capture_filter", "headless"])

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

        version_token = browser_version_token(name, b["path"])
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
                    visit_url(b, url, profile_root, args.page_seconds, args.between_seconds, args.headless, logs_root)
                    if not args.no_close_target_connections:
                        close_target_connections(target_ips, args.connection_settle_seconds)
                    ended = utc_now()
                    visit_rows.append({"browser": name, "rank": str(rank), "domain": domain, "scheme": scheme, "url": url, "pcap_path": str(pcap_path), "start_utc": started, "end_utc": ended})
                    write_csv(visit_path, visit_rows, ["browser", "rank", "domain", "scheme", "url", "pcap_path", "start_utc", "end_utc"])
        finally:
            print(f"Stopping capture for {name}...")
            stop_capture(cap)
        end_utc = utc_now()
        for row in pcap_rows:
            if row.get("browser") == name and row.get("pcap_path") == str(pcap_path):
                row["end_utc"] = end_utc
                row["completed"] = "true"
        write_csv(manifest_path, pcap_rows, ["browser", "pcap_path", "dumpcap_log", "browser_version_token", "site_range", "start_utc", "end_utc", "completed"])

    print(f"Done. Output directory: {run_dir}")
    print(f"PCAP manifest: {manifest_path}")
    print(f"Visit log: {visit_path}")
    print(f"Capture filter: {run_dir / 'capture-filter.txt'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
