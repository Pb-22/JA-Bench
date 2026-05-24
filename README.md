# JA-Bench

JA-Bench is a passive-first Dockerized workbench for extracting, reviewing, enriching, comparing, and exporting network fingerprint data from PCAPs.

It sits in the same general family as [Suricata-Bench](https://github.com/Pb-22/Suricata-Bench), but the center of gravity is different. JA-Bench is for analysts who want to take a capture, inspect what was really present on the wire, derive fingerprint values, optionally run bounded follow-up probes, and keep the results searchable with clear provenance.

## What it does

From a selected PCAP and selected flow, JA-Bench can:

- hash and deduplicate PCAPs by **SHA-256 content hash**
- parse flows and build analyst-friendly flow labels
- extract passive **HTTP**, **TLS**, **certificate**, and related observations
- store **JA3**, **JA3S**, **JA4**, and other collected values
- search local stored data by fingerprint, SNI, cert hash, or IP
- compare passive observations with later active follow-up results
- enrich flows with **optional Shodan** context when a key is configured
- export selected conversation, search results, or all stored results as **JSON** or **CSV**

## Why the HTTP comparison exists

The HTTP comparison view is there to answer a simple analyst question:

> Did the later bounded active request still look like the request shape implied by the original PCAP?

That matters in a few cases:

- a TLS flow has only SNI/passive TLS evidence, and you want a bounded follow-up request to recover minimal HTTP context
- a passive HTTP row shows one path and user-agent, and you want to see whether **Light Testing** or **PCAP-Mimic** stayed aligned with it
- a request changed because of redirect behavior, content negotiation, or environment drift, and you want that difference called out instead of buried in raw output

JA-Bench now compares:

- **passive HTTP** vs **Light Testing HTTP**
- **passive HTTP** vs **PCAP-Mimic HTTP**

and shows whether the request shape matched or changed across fields like method, host, URI, full URL, status, content-type, location, and user-agent.

## Current feature set

### Passive extraction

Current passive work includes:

- PCAP upload
- SHA-256 sample dedupe
- flow parsing
- conversation selector population
- HTTP observation extraction
- TLS observation extraction
- certificate extraction from visible TLS handshake certificate bytes
- fingerprint storage for:
  - `ja3`
  - `ja3s`
  - `ja4`

### Local search

Current local search supports:

- `ja3`
- `ja3s`
- `ja4`
- `jarm`
- `sni`
- `cert_hash`
- `ip`
- `auto`

Search results are sorted so local flow-backed matches come before bundled historical reference hits, and flow-backed matches can jump directly back into stored flow detail.

### Reference matching

JA-Bench ships with bundled historical JA4 seed data and can perform local reference matching against it.

Important note: this bundled JA4 data is historical starter reference material, not live truth.

### Optional enrichment

Current enrichment support:

- **Shodan** host lookup and related stored enrichment rows
- passive-vs-external comparison for supported values like `ja3s` and `jarm`

If no Shodan key is configured, Shodan is skipped and core app behavior still works.

### Light Testing

Current bounded Light Testing support:

- official **Salesforce JARM**
- **TLS cert grab**
- bounded **HTTP/HTTPS metadata probe**

All Light Testing results are clearly labeled with provenance:

- `light_active_probe`

### PCAP-Mimic

Current first PCAP-Mimic support:

- bounded HTTP request-shape replay using observed passive context where available
- reuse of observed host/path and observed user-agent when visible
- redirects off by default
- tight byte caps

PCAP-Mimic results are labeled with provenance:

- `pcap_mimic_active`

### Export

Current export scopes:

- **Selected Conversation**
- **Search Results**
- **All**

Current export formats:

- **CSV**
- **JSON**

## Provenance model

JA-Bench keeps provenance explicit. Current classes include:

- `pcap_observed`
- `pcap_derived`
- `light_active_probe`
- `pcap_mimic_active`
- `third_party_enrichment`
- `reference_historical`

This is a core rule of the project. JA-Bench should stay honest about what came from the source PCAP, what was derived locally, what was collected later via bounded active probing, and what came from outside context.

## Safety model

JA-Bench is designed to be useful without getting sloppy.

Key safety rules:

- passive-first by default
- active behavior is opt-in
- no in-container VPN management
- if you want different egress/location, connect the **host OS** to a VPN first
- no remote browser rendering as part of collection
- no remote script execution
- no automatic file execution
- bounded timeouts
- bounded byte capture
- clear storage of what was actively probed

## Requirements

You should only need:

- **Docker**
- **Docker Compose** plugin (`docker compose`)

You do **not** need to install `tshark`, `sqlite3`, `shodan`, `curl`, `python` packages, or the official JARM code on the host. The container is the runtime boundary.

## Quick start

### 1. Clone the repo

```bash
git clone https://github.com/Pb-22/JA-Bench.git
cd JA-Bench
```

### 2. Optional: configure keys

If you want Shodan enrichment, create a config file:

```bash
cp config/keys.env.example config/keys.env
```

Then add your key:

```dotenv
SHODAN_API_KEY=your_key_here
```

If you do not want Shodan, you can skip this step.

### 3. Build and start JA-Bench

```bash
docker compose up -d --build
```

### 4. Open the UI

JA-Bench listens on:

- <http://localhost:7008>

### 5. Stop it later

```bash
docker compose down
```

## First-run notes

- The SQLite DB is created automatically on startup.
- Bundled historical JA4 seed data is loaded automatically.
- Persistent data lives under:
  - `data/db/`
  - `data/uploads/`
  - `data/output/`
  - `data/cache/`
  - `config/`

## Fresh-customer smoke test

A quick sanity check after startup:

1. open <http://localhost:7008>
2. upload a PCAP
3. click **Read PCAP**
4. select a flow
5. inspect:
   - Passive HTTP / TLS / certificate output
   - JA / Derived Breakdown
   - Search matches
   - Indicator Assessments
6. optionally try:
   - **Run Light JARM**
   - **Grab TLS Cert**
   - **HTTP Metadata**
   - **Run PCAP-Mimic**
   - **Run Shodan Enrichment** if configured

## Docker details

The default UI port is:

- **7008** on the host
- **5000** inside the container

Why 7008:

- it keeps JA-Bench adjacent to Suricata-Bench without colliding with it

## Repo layout

```text
app/
  main.py
  pcap_service.py
  flow_detail_service.py
  light_probe_service.py
  search_service.py
  certificate_service.py
  export_service.py
  enrichment_service.py
  shodan_service.py
  templates/
  static/
config/
  keys.env.example
data/
  cache/
  db/
  output/
  uploads/
seed/
vendor/
Dockerfile
docker-compose.yml
entrypoint.sh
schema.sql
```

## Current limitations

A few honest limits right now:

- bundled JA4 reference data is historical seed material, not live attribution truth
- some captures will not contain certificate messages, so cert extraction will naturally be absent
- TLS-only flows may have active HTTP follow-up rows without a passive HTTP baseline, and JA-Bench will show that explicitly
- broader coverage across stranger PCAP styles is still worth continued testing

## Development notes

If you are developing JA-Bench further, keep these principles intact:

- one-screen UI
- clear copy-friendly output
- provenance always visible
- container is the runtime boundary
- passive and active data should stay distinguishable
- narrower, reliable workflow beats crowded first-release sprawl

## License / bundled third-party code

JA-Bench vendors the official Salesforce JARM implementation under `vendor/jarm/`. Keep its license file with that code.
