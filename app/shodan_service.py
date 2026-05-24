from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess, run
from typing import Any

try:
    import shodan
except ModuleNotFoundError:
    shodan = None

from .config import Config


class ShodanNotConfiguredError(RuntimeError):
    pass


@dataclass
class CacheResult:
    value: dict[str, Any]
    from_cache: bool
    cache_path: Path | None = None


class ShodanService:
    """Credit-aware Shodan helper.

    Design goals:
    - prefer structured API access for JA-Bench internals
    - keep CLI available in the container for manual workflows
    - cache repeat lookups locally to reduce unnecessary credit burn
    - expose small, explicit methods instead of a generic query firehose
    """

    def __init__(
        self,
        api_key: str | None = None,
        cache_root: Path | None = None,
        cache_ttl_seconds: int = 86400,
        cli_path: str = "shodan",
    ) -> None:
        self.api_key = api_key
        self.cache_root = cache_root or (Config.CACHE_DIR / "shodan")
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cli_path = cli_path
        self._api = shodan.Shodan(api_key) if (api_key and shodan is not None) else None

    @property
    def enabled(self) -> bool:
        return bool(self._api)

    def require_api(self):
        if shodan is None:
            raise ShodanNotConfiguredError("Shodan Python package is not installed")
        if not self._api:
            raise ShodanNotConfiguredError("Shodan API key is not configured")
        return self._api

    def info(self, force_refresh: bool = False) -> CacheResult:
        return self._cached_api_call("info", {}, lambda api: api.info(), force_refresh=force_refresh)

    def host(
        self,
        ip: str,
        history: bool = False,
        minify: bool = True,
        force_refresh: bool = False,
    ) -> CacheResult:
        params = {"ip": ip, "history": history, "minify": minify}
        return self._cached_api_call(
            "host",
            params,
            lambda api: api.host(ip, history=history, minify=minify),
            force_refresh=force_refresh,
        )

    def search_tokens(self, query: str, force_refresh: bool = False) -> CacheResult:
        params = {"query": query}
        return self._cached_api_call(
            "search_tokens",
            params,
            lambda api: api.search_tokens(query),
            force_refresh=force_refresh,
        )

    def count(self, query: str, facets: str | None = None, force_refresh: bool = False) -> CacheResult:
        params = {"query": query, "facets": facets}
        return self._cached_api_call(
            "count",
            params,
            lambda api: api.count(query, facets=facets),
            force_refresh=force_refresh,
        )

    def facet_summary(
        self,
        query: str,
        facets: str,
        force_refresh: bool = False,
    ) -> CacheResult:
        return self.count(query=query, facets=facets, force_refresh=force_refresh)

    def search_preview(
        self,
        query: str,
        limit: int = 10,
        facets: str | None = None,
        minify: bool = True,
        force_refresh: bool = False,
    ) -> CacheResult:
        bounded_limit = max(1, min(limit, 100))
        params = {
            "query": query,
            "limit": bounded_limit,
            "facets": facets,
            "minify": minify,
        }
        return self._cached_api_call(
            "search_preview",
            params,
            lambda api: api.search(query, limit=bounded_limit, facets=facets, minify=minify),
            force_refresh=force_refresh,
        )

    def cli_version(self) -> CompletedProcess[str]:
        return run([self.cli_path, "version"], capture_output=True, text=True, check=False)

    def _cached_api_call(
        self,
        operation: str,
        params: dict[str, Any],
        loader,
        force_refresh: bool = False,
    ) -> CacheResult:
        api = self.require_api()
        cache_path = self._cache_path(operation, params)
        if not force_refresh:
            cached = self._read_cache(cache_path)
            if cached is not None:
                return CacheResult(value=cached, from_cache=True, cache_path=cache_path)

        result = loader(api)
        normalized = self._normalize_jsonable(result)
        self._write_cache(cache_path, normalized)
        return CacheResult(value=normalized, from_cache=False, cache_path=cache_path)

    def _cache_path(self, operation: str, params: dict[str, Any]) -> Path:
        payload = json.dumps({"operation": operation, "params": params}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.cache_root / f"{operation}-{digest}.json"

    def _read_cache(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

        created_at = raw.get("_cached_at")
        if not isinstance(created_at, (int, float)):
            return None
        if (time.time() - created_at) > self.cache_ttl_seconds:
            return None
        return raw.get("data")

    def _write_cache(self, path: Path, data: dict[str, Any]) -> None:
        payload = {
            "_cached_at": time.time(),
            "data": data,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _normalize_jsonable(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "items"):
            return dict(value.items())
        raise TypeError(f"Unsupported Shodan response type: {type(value)!r}")
