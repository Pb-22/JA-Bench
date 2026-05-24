# JA-Bench Schema Notes — 2026-05-23

This note defines the first-pass data model direction for JA-Bench.

The goal is to support:

- passive PCAP extraction
- optional active follow-up
- optional enrichment
- durable local search
- clean export
- clear provenance
- later UI display without forcing ugly wide rows

## Schema design principles

1. keep raw observations separate from judgments
2. keep provenance explicit
3. avoid forcing every possible field into one huge row
4. make common search values indexable
5. keep room for TLS, SSH, HTTP, DNS, cert, and derived fingerprint growth
6. store enough detail for export without making the main UI depend on giant horizontal tables

## Main design decision

JA-Bench should not try to store everything in one giant "result row."

Instead, it should use:

- a small set of core entities
- protocol-specific observation tables
- a fingerprint table
- an assessment layer for prevalence / uniqueness / signal commentary
- optional JSON detail blobs where full structured detail matters more than columnar display

This is important because the UI needs to search values like JA4, JA4S, JA3, JA3S, JARM, SNI, IP, and cert hashes without turning the right-side results area into a horizontal mess.

## Core entity map

### 1. runs

A run is one JA-Bench execution against one uploaded sample or one analysis session.

Suggested fields:

- `id`
- `created_at`
- `mode`
  - `passive`
  - `safe_active`
  - `pcap_mimic_active`
- `status`
- `input_type`
  - `pcap_upload`
  - `recollection`
  - `other`
- `input_name`
- `input_sha256`
- `parse_summary_json`
- `notes`

Purpose:

- anchor a full analysis session
- store top-level parse/run status
- support session summary display

### 2. samples

A sample is the source artifact associated with a run.

Important dedupe rule:

- a PCAP should be identified by content hash, not filename
- renaming the same PCAP must not create a second logical sample
- repeated ingestion of the same file bytes should resolve to the existing stored sample record

Suggested fields:

- `id`
- `run_id`
- `filename`
- `sha256` (unique for dedupe)
- `filesize_bytes`
- `capture_start_ts`
- `capture_end_ts`
- `packet_count`
- `conversation_count`
- `protocol_summary_json`
- `source_type`
  - `uploaded_pcap`
  - `recollected_pcap`
  - `derived_artifact`

Purpose:

- preserve metadata about the source capture
- support summary and export

### 3. flows

A flow is the main user-selectable conversation unit.

This table should drive the post-parse conversation dropdown.

Suggested fields:

- `id`
- `sample_id`
- `flow_key`
- `protocol`
- `transport`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `start_ts`
- `end_ts`
- `packet_count`
- `byte_count`
- `client_to_server_packets`
- `server_to_client_packets`
- `selection_label`
- `summary_json`

Notes:

- `selection_label` can cache the dropdown text or a simplified version of it
- `summary_json` can hold quick facts used in the main output or summary pane

Purpose:

- provide the core selectable conversation object
- anchor all protocol observations beneath it

### 4. observations_dns

Suggested fields:

- `id`
- `flow_id` nullable
- `sample_id`
- `query_name`
- `query_type`
- `response_code`
- `answers_json`
- `observed_at`
- `provenance`

Purpose:

- store DNS activity related to the sample or a specific flow

### 5. observations_http

Suggested fields:

- `id`
- `flow_id`
- `request_method`
- `host`
- `uri`
- `full_url` nullable
- `query_string`
- `user_agent`
- `referer`
- `status_code`
- `location_header`
- `request_headers_json`
- `response_headers_json`
- `request_body_summary_json`
- `response_body_summary_json`
- `observed_at`
- `provenance`

Purpose:

- store visible HTTP request/response details
- support the first-URL and redirect-focused use cases

### 6. observations_tls

Suggested fields:

- `id`
- `flow_id`
- `tls_role`
  - `client_hello`
  - `server_hello`
  - `certificate`
  - `session`
- `tls_version_offered`
- `tls_version_negotiated`
- `sni`
- `alpn_json`
- `cipher_suites_json`
- `selected_cipher`
- `extensions_json`
- `supported_groups_json`
- `signature_algorithms_json`
- `grease_present`
- `session_resumption_hint`
- `observed_at`
- `provenance`

Purpose:

- store handshake-level TLS facts in a structured place
- support fingerprint derivation and later display

### 7. certificates

Suggested fields:

- `id`
- `flow_id` nullable
- `tls_observation_id` nullable
- `leaf_sha256`
- `spki_sha256`
- `serial_number`
- `subject_dn`
- `issuer_dn`
- `san_json`
- `not_before`
- `not_after`
- `is_self_signed`
- `chain_position`
- `pem_text` nullable
- `provenance`

Purpose:

- store parsed certificate facts separately from general TLS observations
- support searches by cert-derived values

### 8. observations_ssh

Suggested fields:

- `id`
- `flow_id`
- `protocol_banner_client`
- `protocol_banner_server`
- `kex_algorithms_json`
- `server_host_key_algorithms_json`
- `encryption_algorithms_json`
- `mac_algorithms_json`
- `compression_algorithms_json`
- `languages_json`
- `observed_at`
- `provenance`

Purpose:

- support HASSH / SSH-oriented derivations later

### 9. fingerprints

This is the central search table for derived fingerprint values.

Suggested fields:

- `id`
- `flow_id` nullable
- `sample_id`
- `fingerprint_type`
  - `ja3`
  - `ja3s`
  - `ja4`
  - `ja4s`
  - `jarm`
  - `hassh`
  - `hasshserver`
  - `ja4ssh`
  - future values as needed
- `fingerprint_value`
- `fingerprint_subtype` nullable
- `role`
  - `client`
  - `server`
  - `session`
  - `unknown`
- `source_observation_table`
- `source_observation_id`
- `component_summary_json`
- `display_summary_json`
- `observed_at`
- `provenance`

Purpose:

- keep a single searchable home for all derived fingerprint values
- support quick search without needing the UI to know every protocol table first

### 10. enrichments

Suggested fields:

- `id`
- `run_id`
- `target_type`
  - `ip`
  - `domain`
  - `certificate`
  - `fingerprint`
- `target_value`
- `provider`
  - `shodan`
  - `rdns`
  - `asn_lookup`
  - etc
- `provider_query`
- `result_summary_json`
- `raw_result_json`
- `observed_at`
- `provenance`

Purpose:

- store external context cleanly
- avoid mixing enrichment fields into observation rows

### 11. active_probes

Suggested fields:

- `id`
- `run_id`
- `flow_id` nullable
- `probe_type`
  - `jarm`
  - `tls_cert_grab`
  - `http_metadata`
  - `redirect_check`
  - `pcap_mimic_request`
  - `recollection`
- `target_host`
- `target_port`
- `request_summary_json`
- `response_summary_json`
- `status`
- `started_at`
- `completed_at`
- `provenance`

Purpose:

- preserve active follow-up steps as first-class records
- give the user an audit trail of what was actually probed

### 12. indicator_assessments

This is the main answer to the uniqueness/prevalence problem.

Do not bloat the raw fingerprint row with too many judgment fields.

Instead, store prevalence and signal commentary here.

Suggested fields:

- `id`
- `fingerprint_id`
- `assessment_type`
  - `prevalence`
  - `signal_review`
  - `context_review`
- `source_context`
  - `seen_in_malware_sample`
  - `seen_in_suspicious_sample`
  - `seen_in_unknown_sample`
- `assessment_confidence`
  - `low`
  - `medium`
  - `high`
- `prevalence_class`
  - `unknown`
  - `common`
  - `somewhat_common`
  - `uncommon`
  - `rare`
- `signal_value`
  - `low`
  - `medium`
  - `high`
  - `very_high`
- `evidence_summary_json`
- `notes`
- `assessed_at`
- `provenance`

Purpose:

- keep uniqueness and signal commentary separate from raw facts
- support a collapsible right-side indicator-assessments pane when the user searches a value
- allow reassessment later without mutating the raw observation record

### 13. external_prevalence_observations

This table stores the supporting evidence behind uniqueness judgments.

Suggested fields:

- `id`
- `fingerprint_id`
- `provider`
  - `shodan`
  - `manual`
  - `other`
- `query_value`
- `query_type`
- `result_count` nullable
- `result_scope_note`
- `observed_distribution_json`
- `raw_summary_json`
- `observed_at`
- `provenance`

Purpose:

- separate hard evidence from higher-level assessment language
- support later recalculation of prevalence class or signal value

### 14. reference_datasets

This table tracks bundled or imported reference-data sources that are not live observations from a JA-Bench run.

Suggested fields:

- `id`
- `dataset_key`
- `display_name`
- `description`
- `source`
- `source_date`
- `version`
- `is_historical`
- `license_note`

Purpose:

- preserve the identity and age of historical or starter reference data
- distinguish seeded knowledge from live run data

### 15. reference_fingerprints

This table stores searchable historical or bundled reference fingerprints and their associated metadata.

Suggested fields:

- `id`
- `dataset_id`
- `fingerprint_type`
- `fingerprint_value`
- `related_fingerprint_string`
- `application`
- `library_name`
- `device_name`
- `os_name`
- `user_agent_string`
- `certificate_authority`
- `ja4s_fingerprint`
- `ja4h_fingerprint`
- `ja4x_fingerprint`
- `ja4t_fingerprint`
- `record_source_json`
- `confidence_note`

Purpose:

- support local historical matching when live third-party lookup is unavailable
- preserve useful app / OS / device context from older fingerprint catalogs
- keep reference matching separate from observations captured by current bench runs

### 16. exports

Suggested fields:

- `id`
- `run_id`
- `scope`
  - `selected_conversation`
  - `search_results`
  - `all`
- `format`
  - `csv`
  - `json`
- `filter_summary_json`
- `output_path`
- `created_at`

Purpose:

- track produced export artifacts
- support repeatability and auditability

## Provenance model

Every observation-like table should carry provenance.

Current provenance values:

- `pcap_observed`
- `pcap_derived`
- `active_probe`
- `pcap_mimic_active`
- `third_party_enrichment`

We may later add:

- `recollected_live`
- `manual_annotation`

The user should be able to tell where a value came from.

## What should be indexed

The following fields should be searchable and indexed early.

### High-priority indexes

- `flows.protocol`
- `flows.src_ip`
- `flows.dst_ip`
- `flows.src_port`
- `flows.dst_port`
- `observations_http.host`
- `observations_http.uri`
- `observations_http.full_url`
- `observations_tls.sni`
- `certificates.leaf_sha256`
- `certificates.spki_sha256`
- `certificates.serial_number`
- `fingerprints.fingerprint_type`
- `fingerprints.fingerprint_value`
- `enrichments.target_type`
- `enrichments.target_value`
- `indicator_assessments.prevalence_class`
- `indicator_assessments.signal_value`

### Useful compound indexes

- `fingerprints(fingerprint_type, fingerprint_value)`
- `flows(sample_id, protocol)`
- `observations_http(flow_id, host, uri)`
- `observations_tls(flow_id, sni)`
- `external_prevalence_observations(fingerprint_id, provider)`

## What should stay in JSON

To avoid turning the schema into a brittle monster, keep these as JSON in the first version unless a strong query need appears:

- protocol summary blobs
- TLS extension lists
- cipher suite lists
- supported groups
- signature algorithm lists
- SAN arrays
- request header maps
- response header maps
- body summary details
- evidence summary details
- provider-specific enrichment payloads

This keeps the relational model useful without making every nested protocol list into five join tables too early.

## Search-result display implications

The schema should support a clean right-side search pane without forcing giant horizontal rows.

That means:

- the search pane should likely show a compact summary per match, not every raw field at once
- the user can expand a selected match to see more detail in the JA / derived pane, session summary pane, or indicator-assessments pane
- the schema should support summary views built from `display_summary_json` and `summary_json` fields

This matters because the user does not want normal left/right scrolling inside bench windows or across the browser page.

## Suggested first implementation slice

The first narrow schema slice should support:

1. upload one PCAP
2. create one run
3. create one sample
4. parse and store flows
5. store visible TLS facts for selected flows
6. derive and store JA3 / JA3S / JA4 / JA4S when available
7. show one conversation in the UI
8. export selected conversation or all results as JSON/CSV

That is enough to prove the model without overbuilding.

## Likely later additions

Possible later tables or expansions:

- tags
- user annotations
- named search presets
- saved views
- recollection job details
- provider credential health/status
- grouping/correlation tables for multi-indicator clusters
- detection candidate records built from compound features rather than single values

## Open questions

1. Should recollection be modeled purely as an `active_probes` subtype, or also as its own first-class run/input type?
2. Should the first version store HTTP bodies only as summaries, or optionally preserve small bounded raw excerpts?
3. Should JA-Bench treat a searched fingerprint as the top-level search object, or should search return a mixed result set grouped by target type?
4. How much summary text should be precomputed into `display_summary_json` versus rendered on demand?

## Recommendation

Do not write raw SQL first.

Next step should be a concrete SQLite-oriented schema draft that maps these notes into:

- table definitions
- primary keys / foreign keys
- indexes
- enum handling strategy
- first migration file
