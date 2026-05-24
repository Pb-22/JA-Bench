PRAGMA foreign_keys = ON;

-- JA-Bench initial SQLite schema draft
-- First-pass goal: support passive PCAP ingestion, flow selection,
-- TLS/HTTP observations, fingerprint storage, export tracking,
-- and separate indicator assessment / prevalence evidence.

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('passive', 'safe_active', 'pcap_mimic_active')),
    status TEXT NOT NULL DEFAULT 'created',
    input_type TEXT NOT NULL CHECK (input_type IN ('pcap_upload', 'recollection', 'other')),
    input_name TEXT,
    input_sha256 TEXT,
    parse_summary_json TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT,
    filesize_bytes INTEGER,
    capture_start_ts TEXT,
    capture_end_ts TEXT,
    packet_count INTEGER,
    conversation_count INTEGER,
    protocol_summary_json TEXT,
    source_type TEXT NOT NULL CHECK (source_type IN ('uploaded_pcap', 'recollected_pcap', 'derived_artifact')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    sample_id INTEGER NOT NULL,
    flow_key TEXT,
    protocol TEXT,
    transport TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    start_ts TEXT,
    end_ts TEXT,
    packet_count INTEGER,
    byte_count INTEGER,
    client_to_server_packets INTEGER,
    server_to_client_packets INTEGER,
    selection_label TEXT,
    summary_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sample_id) REFERENCES samples(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations_dns (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    sample_id INTEGER NOT NULL,
    query_name TEXT,
    query_type TEXT,
    response_code TEXT,
    answers_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE SET NULL,
    FOREIGN KEY (sample_id) REFERENCES samples(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations_http (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER NOT NULL,
    request_method TEXT,
    host TEXT,
    uri TEXT,
    full_url TEXT,
    query_string TEXT,
    user_agent TEXT,
    referer TEXT,
    status_code INTEGER,
    location_header TEXT,
    request_headers_json TEXT,
    response_headers_json TEXT,
    request_body_summary_json TEXT,
    response_body_summary_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations_tls (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER NOT NULL,
    tls_role TEXT CHECK (tls_role IN ('client_hello', 'server_hello', 'certificate', 'session')),
    tls_version_offered TEXT,
    tls_version_negotiated TEXT,
    sni TEXT,
    alpn_json TEXT,
    cipher_suites_json TEXT,
    selected_cipher TEXT,
    extensions_json TEXT,
    supported_groups_json TEXT,
    signature_algorithms_json TEXT,
    grease_present INTEGER CHECK (grease_present IN (0, 1)),
    session_resumption_hint TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    tls_observation_id INTEGER,
    leaf_sha256 TEXT,
    spki_sha256 TEXT,
    serial_number TEXT,
    subject_dn TEXT,
    issuer_dn TEXT,
    san_json TEXT,
    not_before TEXT,
    not_after TEXT,
    is_self_signed INTEGER CHECK (is_self_signed IN (0, 1)),
    chain_position INTEGER,
    pem_text TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE SET NULL,
    FOREIGN KEY (tls_observation_id) REFERENCES observations_tls(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS observations_ssh (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER NOT NULL,
    protocol_banner_client TEXT,
    protocol_banner_server TEXT,
    kex_algorithms_json TEXT,
    server_host_key_algorithms_json TEXT,
    encryption_algorithms_json TEXT,
    mac_algorithms_json TEXT,
    compression_algorithms_json TEXT,
    languages_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    flow_id INTEGER,
    sample_id INTEGER NOT NULL,
    fingerprint_type TEXT NOT NULL,
    fingerprint_value TEXT NOT NULL,
    fingerprint_subtype TEXT,
    role TEXT NOT NULL DEFAULT 'unknown' CHECK (role IN ('client', 'server', 'session', 'unknown')),
    source_observation_table TEXT,
    source_observation_id INTEGER,
    component_summary_json TEXT,
    display_summary_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE SET NULL,
    FOREIGN KEY (sample_id) REFERENCES samples(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('ip', 'domain', 'certificate', 'fingerprint')),
    target_value TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_query TEXT,
    result_summary_json TEXT,
    raw_result_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS active_probes (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    flow_id INTEGER,
    probe_type TEXT NOT NULL CHECK (probe_type IN ('jarm', 'tls_cert_grab', 'http_metadata', 'redirect_check', 'pcap_mimic_request', 'recollection')),
    target_host TEXT,
    target_port INTEGER,
    request_summary_json TEXT,
    response_summary_json TEXT,
    status TEXT,
    started_at TEXT,
    completed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS indicator_assessments (
    id INTEGER PRIMARY KEY,
    fingerprint_id INTEGER NOT NULL,
    assessment_type TEXT NOT NULL CHECK (assessment_type IN ('prevalence', 'signal_review', 'context_review')),
    source_context TEXT NOT NULL CHECK (source_context IN ('seen_in_malware_sample', 'seen_in_suspicious_sample', 'seen_in_unknown_sample')),
    assessment_confidence TEXT NOT NULL CHECK (assessment_confidence IN ('low', 'medium', 'high')),
    prevalence_class TEXT CHECK (prevalence_class IN ('unknown', 'common', 'somewhat_common', 'uncommon', 'rare')),
    signal_value TEXT CHECK (signal_value IN ('low', 'medium', 'high', 'very_high')),
    evidence_summary_json TEXT,
    notes TEXT,
    assessed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS external_prevalence_observations (
    id INTEGER PRIMARY KEY,
    fingerprint_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    query_value TEXT,
    query_type TEXT,
    result_count INTEGER,
    result_scope_note TEXT,
    observed_distribution_json TEXT,
    raw_summary_json TEXT,
    observed_at TEXT,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('selected_conversation', 'search_results', 'all')),
    format TEXT NOT NULL CHECK (format IN ('csv', 'json')),
    filter_summary_json TEXT,
    output_path TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reference_datasets (
    id INTEGER PRIMARY KEY,
    dataset_key TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    source TEXT,
    source_date TEXT,
    version TEXT,
    is_historical INTEGER NOT NULL DEFAULT 1 CHECK (is_historical IN (0, 1)),
    license_note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reference_fingerprints (
    id INTEGER PRIMARY KEY,
    dataset_id INTEGER NOT NULL,
    fingerprint_type TEXT NOT NULL,
    fingerprint_value TEXT NOT NULL,
    related_fingerprint_string TEXT,
    application TEXT,
    library_name TEXT,
    device_name TEXT,
    os_name TEXT,
    user_agent_string TEXT,
    certificate_authority TEXT,
    ja4s_fingerprint TEXT,
    ja4h_fingerprint TEXT,
    ja4x_fingerprint TEXT,
    ja4t_fingerprint TEXT,
    record_source_json TEXT,
    confidence_note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dataset_id) REFERENCES reference_datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_samples_run_id ON samples(run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_samples_sha256_unique ON samples(sha256);

CREATE INDEX IF NOT EXISTS idx_flows_sample_id ON flows(sample_id);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_src_port ON flows(src_port);
CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON flows(dst_port);
CREATE INDEX IF NOT EXISTS idx_flows_sample_protocol ON flows(sample_id, protocol);

CREATE INDEX IF NOT EXISTS idx_dns_query_name ON observations_dns(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_sample_id ON observations_dns(sample_id);
CREATE INDEX IF NOT EXISTS idx_dns_flow_id ON observations_dns(flow_id);

CREATE INDEX IF NOT EXISTS idx_http_flow_id ON observations_http(flow_id);
CREATE INDEX IF NOT EXISTS idx_http_host ON observations_http(host);
CREATE INDEX IF NOT EXISTS idx_http_uri ON observations_http(uri);
CREATE INDEX IF NOT EXISTS idx_http_full_url ON observations_http(full_url);
CREATE INDEX IF NOT EXISTS idx_http_flow_host_uri ON observations_http(flow_id, host, uri);

CREATE INDEX IF NOT EXISTS idx_tls_flow_id ON observations_tls(flow_id);
CREATE INDEX IF NOT EXISTS idx_tls_sni ON observations_tls(sni);
CREATE INDEX IF NOT EXISTS idx_tls_flow_sni ON observations_tls(flow_id, sni);

CREATE INDEX IF NOT EXISTS idx_cert_leaf_sha256 ON certificates(leaf_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_spki_sha256 ON certificates(spki_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_serial_number ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_cert_flow_id ON certificates(flow_id);

CREATE INDEX IF NOT EXISTS idx_ssh_flow_id ON observations_ssh(flow_id);

CREATE INDEX IF NOT EXISTS idx_fingerprints_sample_id ON fingerprints(sample_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_flow_id ON fingerprints(flow_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_type ON fingerprints(fingerprint_type);
CREATE INDEX IF NOT EXISTS idx_fingerprints_value ON fingerprints(fingerprint_value);
CREATE INDEX IF NOT EXISTS idx_fingerprints_type_value ON fingerprints(fingerprint_type, fingerprint_value);

CREATE INDEX IF NOT EXISTS idx_enrichments_run_id ON enrichments(run_id);
CREATE INDEX IF NOT EXISTS idx_enrichments_target_type ON enrichments(target_type);
CREATE INDEX IF NOT EXISTS idx_enrichments_target_value ON enrichments(target_value);
CREATE INDEX IF NOT EXISTS idx_enrichments_provider ON enrichments(provider);

CREATE INDEX IF NOT EXISTS idx_active_probes_run_id ON active_probes(run_id);
CREATE INDEX IF NOT EXISTS idx_active_probes_flow_id ON active_probes(flow_id);
CREATE INDEX IF NOT EXISTS idx_active_probes_probe_type ON active_probes(probe_type);

CREATE INDEX IF NOT EXISTS idx_indicator_assessments_fingerprint_id ON indicator_assessments(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_indicator_assessments_prevalence_class ON indicator_assessments(prevalence_class);
CREATE INDEX IF NOT EXISTS idx_indicator_assessments_signal_value ON indicator_assessments(signal_value);

CREATE INDEX IF NOT EXISTS idx_external_prevalence_fingerprint_id ON external_prevalence_observations(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_external_prevalence_provider ON external_prevalence_observations(provider);
CREATE INDEX IF NOT EXISTS idx_external_prevalence_fp_provider ON external_prevalence_observations(fingerprint_id, provider);

CREATE INDEX IF NOT EXISTS idx_exports_run_id ON exports(run_id);
CREATE INDEX IF NOT EXISTS idx_exports_scope ON exports(scope);
CREATE INDEX IF NOT EXISTS idx_exports_format ON exports(format);

CREATE INDEX IF NOT EXISTS idx_reference_datasets_dataset_key ON reference_datasets(dataset_key);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_dataset_id ON reference_fingerprints(dataset_id);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_type_value ON reference_fingerprints(fingerprint_type, fingerprint_value);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_application ON reference_fingerprints(application);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_os_name ON reference_fingerprints(os_name);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_device_name ON reference_fingerprints(device_name);
