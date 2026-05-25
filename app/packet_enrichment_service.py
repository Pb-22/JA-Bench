from __future__ import annotations

import codecs
import ipaddress
import re
from typing import Any

from .shodan_service import ShodanService


def enrich_packet_with_shodan(
    shodan_service: ShodanService,
    packet: dict[str, Any],
    packet_inspector: dict[str, Any] | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    inspector = packet_inspector or {}
    destination_domain = str(inspector.get("destination_domain") or "").strip()
    destination_ip = str(packet.get("dst_ip") or "").strip()

    hostname_query = f"hostname:{destination_domain}" if destination_domain else ""
    hostname_search_payload = None
    candidate_ips: list[str] = []
    if hostname_query:
        hostname_search = shodan_service.search_preview(
            hostname_query,
            limit=5,
            minify=False,
            force_refresh=force_refresh,
        )
        hostname_search_payload = _summarize_hostname_search(hostname_search.value)
        hostname_search_payload["from_cache"] = hostname_search.from_cache
        candidate_ips = [match["ip"] for match in hostname_search_payload["matches"] if match.get("ip")]

    primary_ip = destination_ip if _is_public_ip(destination_ip) else ""
    if not primary_ip:
        primary_ip = next((candidate for candidate in candidate_ips if _is_public_ip(candidate)), "")

    selection_note = _build_selection_note(destination_ip, primary_ip, candidate_ips)
    host_lookup_payload = None
    if primary_ip:
        host_lookup = shodan_service.host(primary_ip, minify=False, force_refresh=force_refresh)
        host_lookup_payload = _summarize_host_lookup(host_lookup.value)
        host_lookup_payload["from_cache"] = host_lookup.from_cache

    return {
        "destination_domain": destination_domain,
        "destination_ip": destination_ip,
        "hostname_query": hostname_query,
        "candidate_ips": candidate_ips,
        "primary_ip": primary_ip,
        "selection_note": selection_note,
        "hostname_search": hostname_search_payload,
        "host_lookup": host_lookup_payload,
    }


def _summarize_hostname_search(payload: dict[str, Any]) -> dict[str, Any]:
    matches = []
    for row in payload.get("matches") or []:
        location = _render_location(row)
        matches.append(
            {
                "ip": str(row.get("ip_str") or ""),
                "port": row.get("port"),
                "organization": str(row.get("org") or row.get("isp") or ""),
                "hostnames": row.get("hostnames") or [],
                "domains": row.get("domains") or [],
                "location": location,
            }
        )
    return {
        "total": payload.get("total"),
        "matches": matches,
    }


def _summarize_host_lookup(payload: dict[str, Any]) -> dict[str, Any]:
    technologies: list[str] = []
    services: list[dict[str, Any]] = []
    certificate = {
        "issuer": "",
        "subject": "",
        "serial": "",
        "alt_names": [],
        "versions": [],
        "jarm": "",
        "ja3s": "",
    }

    for banner in payload.get("data") or []:
        port = banner.get("port")
        service = {
            "port": port,
            "transport": str(banner.get("transport") or ""),
            "product": str(banner.get("product") or ""),
            "version": str(banner.get("version") or ""),
            "http_status": None,
            "http_server": "",
            "http_location": "",
            "http_title": "",
            "data": str(banner.get("data") or "")[:600],
        }
        http = banner.get("http") or {}
        if isinstance(http, dict):
            service["http_status"] = http.get("status")
            service["http_server"] = str(http.get("server") or "")
            service["http_location"] = str(http.get("location") or "")
            service["http_title"] = str(http.get("title") or "")
            components = http.get("components") or {}
            if isinstance(components, dict):
                for name, component in components.items():
                    versions = component.get("versions") or []
                    version_text = str(versions[0]) if versions else ""
                    technologies.append(f"{name} {version_text}".strip())

        ssl = banner.get("ssl") or {}
        if isinstance(ssl, dict):
            if not certificate["jarm"]:
                certificate["jarm"] = str(ssl.get("jarm") or "")
            if not certificate["ja3s"]:
                certificate["ja3s"] = str(ssl.get("ja3s") or "")
            cert = ssl.get("cert") or {}
            if isinstance(cert, dict):
                if not certificate["issuer"]:
                    certificate["issuer"] = _render_name(cert.get("issuer"))
                if not certificate["subject"]:
                    certificate["subject"] = _render_name(cert.get("subject"))
                if not certificate["serial"]:
                    certificate["serial"] = str(cert.get("serial") or "")
                alt_names = _extract_alt_names(cert)
                if alt_names and not certificate["alt_names"]:
                    certificate["alt_names"] = [str(item) for item in alt_names if item]
            versions = ssl.get("versions") or []
            for version in versions:
                version_text = str(version or "").strip()
                if version_text and version_text not in certificate["versions"]:
                    certificate["versions"].append(version_text)

        technologies.extend(_banner_technology_candidates(banner))
        services.append(service)

    technologies = sorted({item for item in technologies if item})

    return {
        "ip": str(payload.get("ip_str") or ""),
        "organization": str(payload.get("org") or ""),
        "isp": str(payload.get("isp") or ""),
        "asn": str(payload.get("asn") or ""),
        "operating_system": str(payload.get("os") or ""),
        "location": _render_location(payload),
        "hostnames": payload.get("hostnames") or [],
        "domains": payload.get("domains") or [],
        "ports": payload.get("ports") or [],
        "technologies": technologies,
        "services": services,
        "certificate": certificate,
    }


def _banner_technology_candidates(banner: dict[str, Any]) -> list[str]:
    values = []
    for key in ("product", "devicetype", "module"):
        value = str(banner.get(key) or "").strip()
        if value:
            version = str(banner.get("version") or "").strip() if key == "product" else ""
            values.append(f"{value} {version}".strip())
    return values


def _render_location(payload: dict[str, Any]) -> str:
    city = str(payload.get("city") or "").strip()
    region = str(payload.get("region_code") or payload.get("region_name") or "").strip()
    country = str(payload.get("country_name") or "").strip()
    parts = [part for part in (city, region, country) if part]
    return ", ".join(parts)


def _render_name(value: Any) -> str:
    if isinstance(value, dict):
        ordered = []
        for key in ("CN", "commonName", "O", "organizationName", "OU", "organizationalUnitName", "C", "countryName"):
            item = str(value.get(key) or "").strip()
            if item:
                ordered.append(f"{key}={item}")
        if ordered:
            return ", ".join(ordered)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    return str(value or "").strip()


def _extract_alt_names(cert: dict[str, Any]) -> list[str]:
    direct_alt_names = cert.get("alt_names") or []
    if isinstance(direct_alt_names, list):
        values = [str(item).strip() for item in direct_alt_names if str(item).strip()]
        if values:
            return values

    extensions = cert.get("extensions") or {}
    if isinstance(extensions, dict):
        subject_alt_names = extensions.get("subject_alt_name", [])
        if isinstance(subject_alt_names, list):
            return [str(item).strip() for item in subject_alt_names if str(item).strip()]
        if isinstance(subject_alt_names, str) and subject_alt_names.strip():
            return [subject_alt_names.strip()]

    if isinstance(extensions, list):
        for extension in extensions:
            if not isinstance(extension, dict):
                continue
            name = str(extension.get("name") or "").strip().lower()
            if name not in {"subjectaltname", "subject_alt_name"}:
                continue
            decoded = _extract_subject_alt_names_from_blob(extension.get("data"))
            if decoded:
                return decoded

    return []


def _extract_subject_alt_names_from_blob(value: Any) -> list[str]:
    text = str(value or "")
    if not text:
        return []
    try:
        text = codecs.decode(text, "unicode_escape")
    except Exception:
        pass
    candidates = []
    for match in re.findall(r"(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", text):
        normalized = match.strip().lower()
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates


def _build_selection_note(destination_ip: str, primary_ip: str, candidate_ips: list[str]) -> str:
    public_candidates = [candidate for candidate in candidate_ips if _is_public_ip(candidate)]
    if destination_ip and primary_ip and destination_ip == primary_ip and _is_public_ip(destination_ip):
        return f"Using packet destination IP {primary_ip} for Shodan host details."
    if primary_ip and len(public_candidates) == 1:
        return f"One public IP was found for the hostname. Using {primary_ip} for host details."
    if primary_ip and len(public_candidates) > 1:
        return f"Multiple public IPs were found for the hostname. Using {primary_ip} for host details."
    return ""


def _is_public_ip(value: str | None) -> bool:
    try:
        ip_obj = ipaddress.ip_address(str(value or ""))
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )
