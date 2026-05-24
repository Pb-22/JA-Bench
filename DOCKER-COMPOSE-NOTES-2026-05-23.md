# JA-Bench Docker / Compose Notes — 2026-05-23

These notes capture the current deployment assumptions that should shape the first scaffold.

## Product shape

JA-Bench is expected to run as a local Docker + Docker Compose application with a browser UI.

The first version should assume one main app container backed by persistent bind mounts or named volumes for:

- uploaded PCAPs
- generated exports
- cache data
- SQLite database storage
- optional config / keys

## Why this matters to the schema

SQLite works well here if the database file lives on a persistent mounted path and we do not treat the container filesystem as durable.

That means the scaffold should assume a stable data path such as:

- `/data/db/ja-bench.sqlite3`

and separate durable directories such as:

- `/data/uploads/`
- `/data/output/`
- `/data/cache/`
- `/data/config/`

## Recommended initial Compose shape

Likely first service layout:

### `ja-bench`

Main app service responsible for:

- web UI
- upload handling
- PCAP parsing
- SQLite reads/writes
- export generation
- optional enrichment calls
- optional active probing logic

Potential later split if needed:

- app/web service
- background worker service

But the first version should stay simple unless async work immediately forces a split.

## Persistence expectations

The container should not lose any of the following on restart:

- SQLite database
- uploaded PCAPs that the user expects to keep
- exports
- cache files that improve repeat work
- local optional config such as enrichment keys

## Suggested mounted paths

Inside container:

- `/app/` for application code
- `/data/db/` for SQLite database file
- `/data/uploads/` for uploaded PCAPs
- `/data/output/` for exports and generated artifacts
- `/data/cache/` for temporary reusable caches
- `/data/config/` for optional local configuration such as API keys

## SQLite-specific considerations in Docker

1. keep the SQLite file on a persistent mounted path
2. do not place the DB in a throwaway temp directory
3. prefer one app process model first, or at least avoid high write contention early
4. enable foreign keys at connection time
5. consider WAL mode later if concurrent reads become important

For the first version, simple and durable matters more than cleverness.

## Optional keys / config

Shodan should be optional, but when configured the CLI should be available in the container path and initialized the way Shodan expects.

Recommended direction:

- install the `shodan` Python package inside the container so the `shodan` command exists in container `PATH`
- store local optional config on a mounted path
- keep secrets out of git
- let the app start and run normally even if no Shodan key exists
- if a key exists, initialize the CLI during container startup

Possible config path:

- `/data/config/keys.env`

Possible environment variable:

- `SHODAN_API_KEY`

Behavior:

- if present, Shodan enrichment can run
- if absent, skip silently
- the container should also provide the `shasum` command for operator use and for parity with content-hash based sample dedupe workflows

## Networking considerations

Because JA-Bench may later do active probing or controlled recollection, Compose choices may matter.

The first version should keep networking straightforward, but leave room for:

- proxy configuration
- alternate egress settings
- controlled DNS behavior
- future worker separation

## Recollection / active follow-up implication

If the project later supports controlled recollection or bounded active request replay, the scaffold should avoid baking in assumptions that all traffic is passive-only.

That does not mean the first version must implement recollection.

It means:

- config paths should have room for active-mode settings later
- the service layout should not block a future worker or probe runner
- persistent storage should be able to hold both uploaded PCAPs and recollected PCAPs

## Suggested first scaffold outputs

When we scaffold, we should likely create:

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `app/`
- `data/uploads/.gitkeep`
- `data/output/.gitkeep`
- `data/cache/.gitkeep`
- `data/db/.gitkeep`
- `config/` or mounted `/data/config/` convention
- application setting for DB path defaulting to `/data/db/ja-bench.sqlite3`

## Recommendation

The first scaffold should assume:

- one app container
- one SQLite database file on a persistent mounted path
- durable upload/output/cache/db directories
- optional config/keys path for Shodan
- later freedom to add a worker without breaking the directory layout
