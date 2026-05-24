# Seed Data

This directory contains optional bundled starter reference data that JA-Bench can import into SQLite on first startup.

Current bundled seed set:

- `reference_ja4plus_db.csv`

Behavior:

- the container initializes the schema on startup
- the seed loader checks whether the corresponding dataset already exists
- if it does not exist yet, the seed data is imported once
- if it already exists, the loader does nothing

This keeps startup idempotent for cloned deployments.
