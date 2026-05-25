PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    mode TEXT NOT NULL DEFAULT 'passive',
    status TEXT NOT NULL DEFAULT 'created',
    input_type TEXT NOT NULL DEFAULT 'pcap_upload',
    input_name TEXT,
    input_sha256 TEXT,
    parse_summary_json TEXT
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    filesize_bytes INTEGER,
    capture_start_ts TEXT,
    capture_end_ts TEXT,
    packet_count INTEGER NOT NULL DEFAULT 0,
    zeek_summary_json TEXT,
    parse_summary_json TEXT,
    source_type TEXT NOT NULL DEFAULT 'uploaded_pcap',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS packet_rows (
    id INTEGER PRIMARY KEY,
    sample_id INTEGER NOT NULL,
    packet_number INTEGER NOT NULL,
    ts_epoch REAL,
    ts_text TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    transport TEXT,
    protocol TEXT,
    length_bytes INTEGER,
    endpoint_text TEXT,
    artifact_summary_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sample_id) REFERENCES samples(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS packet_artifacts (
    id INTEGER PRIMARY KEY,
    sample_id INTEGER NOT NULL,
    packet_id INTEGER NOT NULL,
    artifact_type TEXT NOT NULL,
    artifact_value TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'unknown',
    raw_fingerprint TEXT,
    raw_original_order TEXT,
    parts_json TEXT,
    provenance TEXT NOT NULL DEFAULT 'pcap_derived',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sample_id) REFERENCES samples(id) ON DELETE CASCADE,
    FOREIGN KEY (packet_id) REFERENCES packet_rows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_matches (
    id INTEGER PRIMARY KEY,
    artifact_id INTEGER NOT NULL,
    reference_id INTEGER,
    match_kind TEXT NOT NULL CHECK (match_kind IN ('exact', 'partial')),
    matched_section_count INTEGER NOT NULL DEFAULT 0,
    matched_sections_json TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (artifact_id) REFERENCES packet_artifacts(id) ON DELETE CASCADE,
    FOREIGN KEY (reference_id) REFERENCES reference_fingerprints(id) ON DELETE CASCADE
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

CREATE TABLE IF NOT EXISTS jarm_fingerprints (
    id INTEGER PRIMARY KEY,
    source_packet_id INTEGER,
    source_sample_id INTEGER,
    target_host TEXT NOT NULL,
    target_ip TEXT,
    target_port INTEGER NOT NULL DEFAULT 443,
    destination_domain TEXT,
    jarm_fingerprint TEXT NOT NULL,
    jarm_first_30 TEXT NOT NULL,
    jarm_last_32 TEXT NOT NULL,
    jarm_raw TEXT,
    analyst_note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_packet_id) REFERENCES packet_rows(id) ON DELETE SET NULL,
    FOREIGN KEY (source_sample_id) REFERENCES samples(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_samples_sha256_unique ON samples(sha256);
CREATE INDEX IF NOT EXISTS idx_packet_rows_sample_id ON packet_rows(sample_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_packet_rows_sample_number ON packet_rows(sample_id, packet_number);
CREATE INDEX IF NOT EXISTS idx_packet_artifacts_packet_id ON packet_artifacts(packet_id);
CREATE INDEX IF NOT EXISTS idx_packet_artifacts_sample_id ON packet_artifacts(sample_id);
CREATE INDEX IF NOT EXISTS idx_packet_artifacts_type_value ON packet_artifacts(artifact_type, artifact_value);
CREATE INDEX IF NOT EXISTS idx_artifact_matches_artifact_id ON artifact_matches(artifact_id);
CREATE INDEX IF NOT EXISTS idx_reference_datasets_dataset_key ON reference_datasets(dataset_key);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_dataset_id ON reference_fingerprints(dataset_id);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_type_value ON reference_fingerprints(fingerprint_type, fingerprint_value);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_ja4s ON reference_fingerprints(ja4s_fingerprint);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_ja4h ON reference_fingerprints(ja4h_fingerprint);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_ja4x ON reference_fingerprints(ja4x_fingerprint);
CREATE INDEX IF NOT EXISTS idx_reference_fingerprints_ja4t ON reference_fingerprints(ja4t_fingerprint);
CREATE INDEX IF NOT EXISTS idx_jarm_fingerprints_full ON jarm_fingerprints(jarm_fingerprint);
CREATE INDEX IF NOT EXISTS idx_jarm_fingerprints_first30 ON jarm_fingerprints(jarm_first_30);
CREATE INDEX IF NOT EXISTS idx_jarm_fingerprints_last32 ON jarm_fingerprints(jarm_last_32);
