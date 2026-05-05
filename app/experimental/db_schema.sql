CREATE TABLE IF NOT EXISTS experimental_source_records (
    source_name VARCHAR(32) NOT NULL,
    source_record_id VARCHAR(255) NOT NULL,
    cve_id VARCHAR(64) NOT NULL,
    cve_year INT NOT NULL,
    published_date datetime  NULL,
    last_modified_date datetime  NULL,
    severity VARCHAR(32) NULL,
    base_score DECIMAL(5,2) NULL,
    vendor_names JSON NULL,
    product_names JSON NULL,
    references_json JSON NULL,
    source_url VARCHAR(1024) NULL,
    raw_payload_json LONGTEXT NULL,
    inserted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (source_name, source_record_id),
    KEY idx_esr_source_cve (source_name, cve_id),
    KEY idx_esr_cve_year (cve_year),
    KEY idx_esr_published_date (published_date)
);

CREATE TABLE IF NOT EXISTS experimental_metrics (
    metric_id BIGINT NOT NULL AUTO_INCREMENT,
    scenario_year INT NOT NULL,
    subject_source VARCHAR(32) NOT NULL,
    comparison_source VARCHAR(32) NULL,
    metric_name VARCHAR(128) NOT NULL,
    metric_value DECIMAL(18,6) NOT NULL,
    numerator_value DECIMAL(18,6) NULL,
    denominator_value DECIMAL(18,6) NULL,
    unit VARCHAR(32) NOT NULL DEFAULT 'ratio',
    note TEXT NULL,
    calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (metric_id),
    KEY idx_em_scenario_subject (scenario_year, subject_source),
    KEY idx_em_metric_name (metric_name)
);
