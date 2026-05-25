# JA-Bench

JA-Bench is a Dockerized workbench for analyzing JA-family network fingerprints from two directions:

- read a PCAP and inspect packet-ordered passive fingerprints
- paste a single JA, JA3, HASSH, or JARM value and analyze it directly

The goal is practical analyst workflow, not just extraction. JA-Bench breaks hashes into readable fields, adds protocol-aware inferences, checks local historical matches, lets you save curated reference entries, and keeps the provenance clear.

## What JA-Bench does

- Upload one PCAP and render a packet-first analysis window
- Extract passive fingerprints including:
  - `JA4`
  - `JA4S`
  - `JA4H`
  - `JA4T`
  - `JA4TS`
  - `JA4L`
  - `JA4LS`
  - `JA4X`
  - `JA4SSH`
  - `JA4D`
  - `JA4D6`
  - `JA3`
  - `JA3S`
  - `HASSH`
- Run an offline Zeek pass for each uploaded capture
- Show field-level breakdowns, conclusions, and citations for each artifact
- Compare artifacts against bundled historical reference data and local analyst-curated entries
- Save analyst-curated reference rows directly from packet artifacts
- Run optional active JARM against a destination domain from packet context
- Save JARM fingerprints with analyst notes
- Analyze a single pasted hash without needing a PCAP
- Export the analyst-facing JA reference table, JARM table, or both as `CSV`, `JSON`, or `JSONL / NDJSON`

## Main workflows

### 1. Packet-first PCAP analysis

Use this when you have a capture and want the full passive context.

- Upload a PCAP
- Read packet rows in order
- Expand a row to inspect:
  - artifact breakdowns
  - conclusions and inferences
  - packet-side context
  - saved historical matches
  - analyst save actions
  - optional JARM and Shodan enrichment where relevant

### 2. Direct hash analysis

Use this when you already have a fingerprint and want to understand it quickly.

- Choose the hash type
- Paste the value
- Get:
  - the field breakdown
  - protocol-aware conclusions and inferences
  - saved local matches
  - a direct save path into the analyst reference table or JARM table

This mode intentionally skips packet context and does not offer active JARM lookup. It is for one-hash-at-a-time analysis and curation.

## Why this project exists

Most fingerprint tools stop at extraction. JA-Bench is meant to be the place where an analyst actually works the result:

- inspect what the hash means
- compare it to known local history
- add analyst knowledge that is not in the original PCAP
- keep the saved data searchable and exportable

## Optional enrichment

JA-Bench works without external services, but can optionally use:

- Shodan host enrichment
- active JARM from packet context

Those results are kept separate from passive observations so you can tell what came from the PCAP and what came from follow-up activity.

## Export model

JA-Bench treats analyst tables as the export surface.

- `JA Reference Table`
- `JARM Table`
- `JA + JARM Tables`

The packet cache and upload history stay local operational data. They are not the primary interchange format.

## Quick start

```bash
git clone git@github.com:Pb-22/JA-Bench.git
cd JA-Bench
docker compose up -d --build
```

Open:

- <http://localhost:7009>

## Optional Shodan configuration

If you want Shodan enrichment:

```bash
cp config/keys.env.example config/keys.env
```

Then set:

```dotenv
SHODAN_API_KEY=your_key_here
```

If you do not configure a key, the rest of JA-Bench still works.

## Storage

Persistent project data lives under:

- `data/db/`
- `data/uploads/`
- `data/output/`
- `data/cache/`
- `data/zeek/`

The default SQLite database path is:

- `data/db/ja-bench.sqlite3`

## Requirements

You only need:

- Docker
- Docker Compose plugin

The container handles the Python dependencies, Zeek, tshark support, and the rest of the runtime.
