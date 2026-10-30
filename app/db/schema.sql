CREATE TABLE IF NOT EXISTS uploads (
    id           TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    language     TEXT,
    stored_name  TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                 TEXT PRIMARY KEY,
    input_type         TEXT NOT NULL CHECK (input_type IN ('code', 'http')),
    input_ref          TEXT,
    filename           TEXT,
    language           TEXT,
    status             TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','DONE','FAILED')),
    stage              TEXT,
    model              TEXT,
    prompt_tokens      INTEGER DEFAULT 0,
    completion_tokens  INTEGER DEFAULT 0,
    duration_ms        INTEGER,
    llm_output_invalid INTEGER DEFAULT 0,
    cached             INTEGER DEFAULT 0,
    suspicious_json    TEXT,
    error              TEXT,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    job_id         TEXT NOT NULL REFERENCES scan_jobs(id),
    vuln_type      TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('HIGH','MEDIUM','LOW')),
    confidence     REAL,
    location_type  TEXT CHECK (location_type IN ('line','param','header')),
    location       TEXT,
    line_start     INTEGER,
    line_end       INTEGER,
    rule_id        TEXT,
    cwe_id         TEXT,
    evidence       TEXT,
    description    TEXT,
    suggestion     TEXT,
    source_channel TEXT NOT NULL CHECK (source_channel IN ('rule','llm','both')),
    knowledge_json TEXT,
    factors_json   TEXT,
    raw_json       TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS repairs (
    id             TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL REFERENCES findings(id),
    patch_diff     TEXT,
    patched_path   TEXT,
    syntax_ok      INTEGER,
    rescan_clean   INTEGER,
    llm_verified   INTEGER,
    verified       INTEGER,
    notes          TEXT,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_repairs_finding ON repairs(finding_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uploads_sha ON uploads(sha256);
