# JA-Bench — Start Here

If we are resuming JA-Bench after a pivot, read this file first.

## What JA-Bench is

JA-Bench is a new project under `/home/claw/.openclaw/workspace/projects/JA-Bench/`.

It is intended to be a Docker + Docker Compose + browser-UI workbench, broadly parallel in spirit to Suricata-Bench, but focused on collecting and analyzing network fingerprints and related observables from PCAPs and optional active probes.

## Current naming decision

- Final chosen project name: `JA-Bench`
- We considered `collectionJAr`, but decided `JA-Bench` is clearer and sits more naturally next to Suricata-Bench.

## Core project intent

JA-Bench should collect as much honest network-observable data as possible, especially around TLS and adjacent protocol fingerprints.

The initial scope includes:
- passive PCAP extraction
- TLS/client/server fingerprint collection
- certificate parsing and enrichment
- optional active probing
- browser-based review UI
- local persistence in SQLite
- export to JSON and CSV

## Fingerprints and observables to target

### Passive from PCAP
- JA3
- JA3S
- JA4
- JA4S
- SNI
- ALPN
- TLS versions
- offered ciphers
- selected cipher
- extension list and ordering
- supported groups
- signature algorithms
- GREASE presence
- session ticket / resumption hints
- certificate chain details when visible
- leaf cert SHA256
- SPKI SHA256
- certificate serial
- issuer / subject / SANs / validity
- DNS lookups
- IPs / ports
- HTTP headers and URIs if visible
- timing / retry behavior
- in-band geolocation lookups observed in the sample traffic itself

### Enrichment / external facts
- Shodan enrichment
- certificate serial and other cert facts from external sources where available
- ASN / org / country
- reverse DNS where useful

### Active probing
- JARM
- TLS cert grab
- minimal HTTP/HTTPS metadata probe
- optional redirect capture
- optional PCAP-mimic request replay in the most active mode

## Active-mode model

JA-Bench should have at least three modes:

### 1. Passive
- PCAP analysis only
- no outbound traffic

### 2. Light testing
- official JARM probing
- later TLS cert grab
- later minimal metadata collection
- no file download
- no browser rendering
- no script execution

### 3. PCAP-mimic active
- replay only the request shape visible in the source PCAP
- may mimic method, URI/path, headers, body shape, or other safely reproducible observables
- should not claim to reproduce malware behavior beyond what is honestly visible in the capture
- should not follow redirects by default
- should not retrieve files beyond tight configured limits

## Important design boundary

JARM is an active TLS handshake fingerprint. It does not by itself capture an HTTP URI or redirect target.

If JA-Bench captures the first URI, redirect, or minimal HTTP response metadata after probing, that should be implemented as a separate optional HTTP/HTTPS probe stage, not mislabeled as JARM.

## Safety model

JA-Bench should be designed so active use does not casually expose the user or behave unsafely.

Safety expectations:
- passive mode should be the default
- active mode must be opt-in
- JA-Bench should not try to manage VPNs inside the container
- if the operator wants different source location or IP, they should connect the host OS to a VPN before running active probes
- never execute remote content
- never render remote content in a browser engine as part of collection
- no automatic file execution
- no automatic decompression/execution pipeline
- timeout caps
- byte caps
- clear audit trail of what was actively probed
- clear labeling of what came from PCAP, what came from active probing, and what came from third-party enrichment

## Data model direction

JA-Bench should use SQLite for local persistence.

Why:
- simple and durable local storage
- easy browser UI backend
- good fit for per-run, per-host, per-fingerprint views
- easy export to JSON and CSV

Likely entity areas:
- runs
- samples
- flows
- dns observations
- http observations
- tls observations
- certificates
- fingerprints
- enrichments
- active probes
- artifacts / exports

## Provenance rule

Every stored fact should preserve where it came from. Example provenance classes:
- `pcap_observed`
- `pcap_derived`
- `light_active_probe`
- `pcap_mimic_active`
- `third_party_enrichment`

This matters because JA-Bench should stay honest about what was actually seen in the source PCAP versus what we learned later from probing or enrichment.

## Deployment model

JA-Bench should run in Docker with Docker Compose and expose a browser UI, similar in general product shape to Suricata-Bench.

Likely project structure:
- `app/`
- `app/templates/`
- `app/static/`
- `app/collectors/`
- `data/uploads/`
- `data/output/`
- `data/cache/`
- `Dockerfile`
- `docker-compose.yml`
- `entrypoint.sh`
- `README.md`
- `START-HERE.md`

## Current status

JA-Bench is now an early working prototype, not just a design.

What has been decided:
- name: `JA-Bench`
- location: `/home/claw/.openclaw/workspace/projects/JA-Bench/`
- Docker + Docker Compose + browser UI
- SQLite persistence
- JSON/CSV export
- passive-first with optional active probing
- most-active mode may mimic the request shape seen in the source PCAP
- one-screen UI, wider than Suricata-Bench, with a clean analyst-first layout
- explicit conversation selection after reading a PCAP
- separate panes for main output, quick-search matches, JA/derived interpretation, session summary, and logs
- export controls should use Scope + Format selectors instead of many separate export buttons
- Shodan enrichment is optional and should silently skip when no key is configured
- historical JA4-related starter reference data can be bundled and auto-seeded into SQLite for new deployments
- sample dedupe should be based on PCAP content hash (SHA-256), not filename, so renamed re-runs do not create duplicate rows

What is still open:
- richer active-probe summary rendering and small UI polish
- broader click-through/search navigation improvements as the local corpus grows
- deciding whether HTTP-metadata probe results need more first-class reporting beyond normalized HTTP observation rows and active-probe summaries
- how much operator-supplied egress context to expose in the UI, while keeping VPN/location changes outside the container

## UI design note added

Read this next for the current UI direction:

- `/home/claw/.openclaw/workspace/projects/JA-Bench/DESIGN-NOTES-2026-05-23.md`

Key UI decisions captured there:
- one screen only
- top row with Browse, filename display, and Read PCAP
- conversation dropdown after parse
- top-right mode selector and quick search
- large copy-friendly main output pane
- wide no-wrap search-results pane
- separate JA / derived breakdown pane
- compact session-summary pane below the JA pane and above theme/export controls
- one quick-search field only, no second search box for now
- export scopes are Selected Conversation, Search Results, and All
- export formats are CSV and JSON

## Best next steps

1. use `DESIGN-NOTES-2026-05-23.md` as the UI/build guide
2. create `README.md` with project overview and scope, aligned to the design notes
3. sketch the SQLite schema
4. define collector modules and output contracts
5. scaffold Docker, Compose, and the browser UI skeleton
6. decide the first narrow end-to-end slice to implement

## Resume prompt

When restarting this project, use a prompt like:

> Read JA-Bench START-HERE and DESIGN-NOTES-2026-05-23, then summarize the passive vs active modes, the safety model, the single-screen UI layout, the export/search model, and the first implementation slice you recommend.

## Latest handoff update

As of 2026-05-24, the latest working prototype includes passive PCAP parsing, selected-flow detail, certificate extraction, bundled reference matching, opt-in Shodan enrichment, official in-container Light Testing JARM, passive-vs-tested JARM comparison, export wiring, the fixed built-in theme selector, real Light Testing TLS cert grab, bounded HTTP/HTTPS metadata probing, and the first bounded PCAP-Mimic HTTP path.

Important restart facts:
- keep the app on one screen
- keep the visual style clean and close in spirit to Suricata-Bench
- require conversation selection after parsing a PCAP that contains multiple flows
- keep the main output copy-friendly
- keep quick search to one field only
- local quick search now supports JA3, JA3S, JA4, JARM, SNI, cert hash, and IP
- search results can jump back into matching stored flows
- active HTTP-style probes now also write normalized `observations_http` rows with `light_active_probe` or `pcap_mimic_active` provenance instead of living only as opaque JSON blobs
- the main flow view now separates passive HTTP, Light Testing HTTP, and PCAP-Mimic HTTP, and includes a passive-vs-active HTTP comparison summary so request-shape drift is obvious
- keep Shodan optional, with silent skip if the key is absent
- do not add VirusTotal at this stage
- do not try to solve VPN/region shifting inside the container; document host-managed VPN as an operator tip instead

If resuming after a break, read the design notes before writing UI code or README text.
