# JA-Bench Shodan Integration Notes — 2026-05-23

This note captures the first integration direction for Shodan in JA-Bench.

## Guiding constraints

- Shodan is optional
- credits are limited, especially on lower tiers
- JA-Bench should avoid wasteful repeat searches
- structured data matters more than simply shelling out to a command and scraping text
- the CLI should still exist in the container path for manual use and later fallback workflows

## Chosen first direction

JA-Bench now has a small API-first Shodan service layer.

Why:

- `api.host()` gives structured host data that is easier to store than raw CLI output
- `api.count(query, facets=...)` is a better fit for prevalence and uniqueness summaries than broad result retrieval
- `api.search_tokens(query)` helps inspect a query before using it more heavily
- `api.search(... limit=small_number ...)` can be used for small previews when needed

The CLI still matters because:

- the `shodan` command is familiar
- the user may want to run `shodan host <ip>` manually inside the container
- later workflows may still use `shodan download` and `shodan parse`
- the container should pin a compatible `setuptools` version because the current Shodan CLI still expects `pkg_resources`

## Credit-aware usage direction

Preferred order of operations:

1. use cached prior result if present and fresh
2. use `host` lookups for single-IP context
3. use `count(..., facets=...)` for prevalence-style summaries
4. use small `search_preview` only when we need example banners
5. reserve bulk download workflows for explicit higher-value cases

## Current helper methods

The first service layer exposes:

- `info()`
- `host(ip, history=False, minify=True)`
- `search_tokens(query)`
- `count(query, facets=None)`
- `facet_summary(query, facets)`
- `search_preview(query, limit=10, facets=None, minify=True)`
- `cli_version()`

## Cache behavior

Responses are cached under:

- `/data/cache/shodan/`

Current default cache TTL:

- 86400 seconds
- 24 hours

This reduces unnecessary repeated calls while we are iterating on the UI and search logic.

## Likely JA-Bench use cases

1. `host` lookup by IP from a selected flow
2. prevalence checks for a JARM or JA3S style value using query + facets
3. small result previews to understand whether a value is common or strongly clustered
4. later support for saving external prevalence evidence into `external_prevalence_observations`
5. later support for turning summary evidence into `indicator_assessments`

## Notes on filters and facets

Shodan uses **filters** in the query syntax and **facets** for summary/distribution breakdowns.

That distinction matters for JA-Bench:

- filters help us form precise searches
- facets help us judge prevalence and clustering

Useful filter families confirmed from the user-provided filter-reference PDF:

- general: `ip`, `port`, `org`, `isp`, `asn`, `country`, `city`, `domain`, `hostname`, `os`, `product`, `version`, `net`, `scan`, `vuln`, `tag`
- HTTP: `http.component`, `http.component_category`, `http.dom_hash`, `http.favicon.hash`, `http.headers_hash`, `http.html`, `http.html_hash`, `http.robots_hash`, `http.securitytxt`, `http.server_hash`, `http.status`, `http.title`, `http.title_hash`, `http.waf`
- SSL/TLS: `ssl`, `ssl.alpn`, `ssl.cert.alg`, `ssl.cert.expired`, `ssl.cert.extension`, `ssl.cert.fingerprint`, `ssl.cert.issuer.cn`, `ssl.cert.pubkey.bits`, `ssl.cert.pubkey.type`, `ssl.cert.serial`, `ssl.cert.subject.cn`, `ssl.chain_count`, `ssl.cipher.bits`, `ssl.cipher.name`, `ssl.cipher.version`, `ssl.ja3s`, `ssl.jarm`, `ssl.version`
- SSH: `ssh.hassh`, `ssh.type`
- cloud: `cloud.provider`, `cloud.region`, `cloud.service`
- screenshots: `screenshot.hash`, `screenshot.label`
- SNMP: `snmp.contact`, `snmp.location`, `snmp.name`
- NTP: `ntp.ip`, `ntp.ip_count`, `ntp.more`, `ntp.port`
- Telnet: `telnet.do`, `telnet.dont`, `telnet.option`, `telnet.will`, `telnet.wont`
- Bitcoin: `bitcoin.ip`, `bitcoin.ip_count`, `bitcoin.port`, `bitcoin.version`

Immediate JA-Bench implication:

- `ssl.jarm` is explicitly supported as a filter
- `ssl.ja3s` is explicitly supported as a filter
- I did **not** see a JA4 filter in the Shodan reference PDF, so we should not assume direct JA4 search support there

## Sources

- Python tutorial: https://shodan.readthedocs.io/en/latest/tutorial.html
- Python API reference: https://shodan.readthedocs.io/en/latest/api.html
- CLI installation: https://help.shodan.io/command-line-interface/0-installation
- CLI getting started: https://help.shodan.io/command-line-interface/1-getting-started
- CLI search/download: https://help.shodan.io/command-line-interface/2-search-download
- CLI stats/facets: https://help.shodan.io/command-line-interface/3-stats
- Query fundamentals: https://help.shodan.io/the-basics/search-query-fundamentals
- Filter reference: https://www.shodan.io/search/filters
