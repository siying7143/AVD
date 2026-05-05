import os
from dotenv import load_dotenv

load_dotenv()

# Central database settings are read from .env so local, test, and production
# deployments can use different MySQL credentials without code changes.
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "avd"),
    "charset": "utf8mb4",
    "autocommit": False,
    "init_command": "SET SESSION time_zone = '+09:30'",
}

# Table names are configurable to support experiments or deployments that use
# separate schemas while keeping the SQL-building code reusable.
DB_TABLE_VULNERABILITIES = os.getenv("DB_TABLE_VULNERABILITIES", "vulnerabilities")
DB_TABLE_AVD_ENTRIES = os.getenv("DB_TABLE_AVD_ENTRIES", "avd_entries")
DB_TABLE_AVD_ASSESSMENTS = os.getenv("DB_TABLE_AVD_ASSESSMENTS", "avd_assessments")

# External feed endpoints used by the import and enrichment pipeline.
NVD_FEED_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Default import window for the core pipeline. Change this list when you want
# `python -m app.main` to ingest a different set of CVE publication years.
DEFAULT_YEARS = [2026, 2025, 2024, 2023]
BATCH_SIZE = 500
REQUEST_TIMEOUT = 180
SOURCE_NAME = "NVD"