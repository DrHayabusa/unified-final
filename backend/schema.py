SCHEMA_VERSION = 1

SCHEMA_SQL = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS customers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    asset_scope_mode text NOT NULL DEFAULT 'observed' CHECK (asset_scope_mode IN ('observed', 'inventory')),
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    full_name text NOT NULL,
    password_hash text NOT NULL,
    global_role text NOT NULL DEFAULT 'customer_user' CHECK (global_role IN ('system_admin', 'customer_user')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS customer_memberships (
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('owner', 'analyst', 'viewer')),
    asset_types text[] NOT NULL DEFAULT ARRAY[]::text[],
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (customer_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    csrf_token text NOT NULL,
    user_agent text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    key_hash text PRIMARY KEY,
    failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    reset_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customer_teams (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name text NOT NULL,
    code text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, code)
);
CREATE UNIQUE INDEX IF NOT EXISTS customer_teams_name_idx ON customer_teams (customer_id, lower(name));

CREATE TABLE IF NOT EXISTS customer_assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    asset_key text NOT NULL,
    ip_address text NOT NULL DEFAULT '',
    dns_name text NOT NULL DEFAULT '',
    host_name text NOT NULL DEFAULT '',
    external_id text NOT NULL DEFAULT '',
    platform text NOT NULL DEFAULT '',
    asset_type text NOT NULL DEFAULT 'Other' CHECK (asset_type IN (
        'Network Device', 'Linux Server', 'Windows Server', 'Endpoint', 'Database',
        'Cloud Asset', 'Security Appliance', 'Virtualization Host',
        'Container Platform', 'OT Device', 'Other'
    )),
    onboarding_tool text NOT NULL DEFAULT 'manual' CHECK (onboarding_tool IN (
        'manual', 'tenable-sc', 'tenable-io', 'qualys', 'crowdstrike',
        'openshift', 'mdvm', 'multi-tool', 'other'
    )),
    team_id uuid REFERENCES customer_teams(id) ON DELETE SET NULL,
    business_unit text NOT NULL DEFAULT '',
    criticality text NOT NULL DEFAULT '',
    internet_exposed boolean,
    origin text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'scanner')),
    in_scope boolean NOT NULL DEFAULT true,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, asset_key)
);

CREATE TABLE IF NOT EXISTS customer_asset_aliases (
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    asset_id uuid NOT NULL REFERENCES customer_assets(id) ON DELETE CASCADE,
    alias text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (customer_id, alias)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id uuid PRIMARY KEY,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    tenant_key text NOT NULL,
    customer_name text NOT NULL,
    ingestion_key text NOT NULL,
    workflow text NOT NULL CHECK (workflow IN ('adhoc', 'monthly', 'quarterly', 'quarterly-scan')),
    source_tool text NOT NULL,
    source_label text NOT NULL,
    report_period text NOT NULL,
    file_names text[] NOT NULL DEFAULT '{}',
    source_ids text[] NOT NULL DEFAULT '{}',
    expected_findings integer NOT NULL CHECK (expected_findings > 0),
    received_findings integer NOT NULL DEFAULT 0 CHECK (received_findings >= 0),
    weighted_findings bigint NOT NULL DEFAULT 0 CHECK (weighted_findings >= 0),
    expected_chunks integer NOT NULL CHECK (expected_chunks > 0),
    received_chunks integer NOT NULL DEFAULT 0 CHECK (received_chunks >= 0),
    status text NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'ready', 'failed')),
    dashboard jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    UNIQUE (customer_id, ingestion_key)
);

CREATE TABLE IF NOT EXISTS ingestion_chunks (
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chunk_index integer NOT NULL CHECK (chunk_index >= 0),
    start_index integer NOT NULL CHECK (start_index >= 0),
    row_count integer NOT NULL CHECK (row_count > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_run_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS finding_observations (
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    row_index integer NOT NULL CHECK (row_index >= 0),
    report_period text NOT NULL,
    report_period_date date,
    finding_key text NOT NULL,
    source_tool text NOT NULL,
    source_tools text[] NOT NULL DEFAULT '{}',
    source_display text NOT NULL DEFAULT '',
    source_vulnerability_id text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    dns_name text NOT NULL DEFAULT '',
    vulnerability_name text NOT NULL DEFAULT '',
    cve text NOT NULL DEFAULT '',
    severity text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown')),
    exploit_available boolean NOT NULL DEFAULT false,
    exploit_signal text NOT NULL DEFAULT '',
    epss_score double precision CHECK (epss_score IS NULL OR epss_score BETWEEN 0 AND 1),
    patch_priority text NOT NULL CHECK (patch_priority IN ('P1', 'P2', 'P3', 'P4')),
    asset_exposure smallint NOT NULL DEFAULT 0 CHECK (asset_exposure BETWEEN 0 AND 1000),
    vulnerability_finding text NOT NULL DEFAULT '',
    summary text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    remediation text NOT NULL DEFAULT '',
    kb_links text NOT NULL DEFAULT '',
    platform_details text NOT NULL DEFAULT '',
    first_discovered date,
    last_observed date,
    vulnerability_age_days integer CHECK (vulnerability_age_days IS NULL OR vulnerability_age_days >= 0),
    protocol text NOT NULL DEFAULT '',
    port text NOT NULL DEFAULT '',
    record_count integer NOT NULL DEFAULT 1 CHECK (record_count > 0),
    datacentre text NOT NULL DEFAULT '',
    times_detected integer NOT NULL DEFAULT 1 CHECK (times_detected > 0),
    vendor_severity_label text NOT NULL DEFAULT '',
    vulnerability_status text NOT NULL DEFAULT '',
    vulnerability_confidence text NOT NULL DEFAULT '',
    exploit_evidence_source text NOT NULL DEFAULT '',
    threat text NOT NULL DEFAULT '',
    impact text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    asset_criticality text NOT NULL DEFAULT '',
    internet_exposed boolean NOT NULL DEFAULT false,
    internet_exposure_known boolean NOT NULL DEFAULT false,
    cisa_kev boolean NOT NULL DEFAULT false,
    namespace text NOT NULL DEFAULT '',
    deployment text NOT NULL DEFAULT '',
    image text NOT NULL DEFAULT '',
    component text NOT NULL DEFAULT '',
    fixable boolean NOT NULL DEFAULT false,
    fixable_signal text NOT NULL DEFAULT '',
    fixed_in text NOT NULL DEFAULT '',
    cvss_score double precision CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    normalized_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (scan_run_id, row_index)
);

CREATE TABLE IF NOT EXISTS threat_intel_imports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ingestion_key text NOT NULL,
    source_label text NOT NULL,
    file_names text[] NOT NULL DEFAULT '{}',
    expected_records integer NOT NULL CHECK (expected_records > 0),
    received_records integer NOT NULL DEFAULT 0 CHECK (received_records >= 0),
    status text NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'ready', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    UNIQUE (customer_id, ingestion_key)
);

CREATE TABLE IF NOT EXISTS threat_intel_records (
    import_id uuid NOT NULL REFERENCES threat_intel_imports(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    row_index integer NOT NULL CHECK (row_index >= 0),
    cve text NOT NULL DEFAULT '',
    vulnerability_name text NOT NULL DEFAULT '',
    source_tool text NOT NULL DEFAULT '',
    source_vulnerability_id text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    dns_name text NOT NULL DEFAULT '',
    severity text NOT NULL DEFAULT 'Unknown',
    patch_priority text NOT NULL DEFAULT 'P4',
    exploit_available boolean NOT NULL DEFAULT false,
    vulnerability_confidence text NOT NULL DEFAULT '',
    exploit_evidence text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    remediation text NOT NULL DEFAULT '',
    kb_links text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    platform_details text NOT NULL DEFAULT '',
    namespace text NOT NULL DEFAULT '',
    deployment text NOT NULL DEFAULT '',
    image text NOT NULL DEFAULT '',
    component text NOT NULL DEFAULT '',
    fixable boolean NOT NULL DEFAULT false,
    fixed_in text NOT NULL DEFAULT '',
    cvss_score double precision CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    first_observed date,
    last_observed date,
    normalized_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (import_id, row_index)
);

CREATE TABLE IF NOT EXISTS threat_intel_enrichments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    query text NOT NULL,
    model text NOT NULL,
    evidence_count integer NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
    response_text text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    customer_id uuid REFERENCES customers(id) ON DELETE SET NULL,
    event_type text NOT NULL,
    event_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip_address text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions (expires_at);
CREATE INDEX IF NOT EXISTS customer_memberships_user_idx ON customer_memberships (user_id, customer_id);
CREATE INDEX IF NOT EXISTS customer_memberships_asset_types_idx ON customer_memberships USING gin (asset_types);
CREATE INDEX IF NOT EXISTS customer_assets_scope_idx ON customer_assets (customer_id, in_scope, asset_type);
CREATE INDEX IF NOT EXISTS customer_assets_identity_idx ON customer_assets (customer_id, ip_address, dns_name);
CREATE INDEX IF NOT EXISTS customer_assets_team_idx ON customer_assets (customer_id, team_id, in_scope);
CREATE INDEX IF NOT EXISTS customer_assets_tool_idx ON customer_assets (customer_id, onboarding_tool, in_scope);
CREATE INDEX IF NOT EXISTS scan_runs_history_idx ON scan_runs (customer_id, status, finalized_at DESC);
CREATE INDEX IF NOT EXISTS finding_period_idx ON finding_observations (scan_run_id, report_period_date, patch_priority, severity);
CREATE INDEX IF NOT EXISTS finding_asset_idx ON finding_observations (dns_name, ip_address);
CREATE INDEX IF NOT EXISTS finding_vulnerability_idx ON finding_observations (cve, source_vulnerability_id);
CREATE INDEX IF NOT EXISTS finding_datacentre_idx ON finding_observations (scan_run_id, datacentre) WHERE datacentre <> '';
CREATE INDEX IF NOT EXISTS finding_openshift_idx ON finding_observations (scan_run_id, namespace, deployment) WHERE namespace <> '' OR deployment <> '';
CREATE INDEX IF NOT EXISTS threat_record_cve_idx ON threat_intel_records (customer_id, lower(cve));
CREATE INDEX IF NOT EXISTS threat_record_name_idx ON threat_intel_records (customer_id, lower(vulnerability_name));
CREATE INDEX IF NOT EXISTS threat_record_asset_idx ON threat_intel_records (customer_id, lower(ip_address), lower(dns_name));
CREATE INDEX IF NOT EXISTS threat_enrichment_idx ON threat_intel_enrichments (customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_customer_idx ON audit_events (customer_id, created_at DESC);
"""
