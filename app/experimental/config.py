import os

from dotenv import load_dotenv


load_dotenv()

# Scenario years and source settings drive the cross-database comparison runner.
EXPERIMENTAL_SCENARIO_YEARS = [2023, 2024, 2025]

EXPERIMENTAL_TABLE_SOURCE_RECORDS = os.getenv(
    "DB_TABLE_EXPERIMENTAL_SOURCE_RECORDS",
    "experimental_source_records",
)
EXPERIMENTAL_TABLE_METRICS = os.getenv(
    "DB_TABLE_EXPERIMENTAL_METRICS",
    "experimental_metrics",
)

SOURCE_NVD = "NVD"
SOURCE_CVE = "CVE"
SOURCE_JVN = "JVN"
SOURCE_EUVD = "EUVD"
SOURCE_GHAD = "GHAD"
SOURCE_AVD = "AVD"

# Only these source names are accepted by --sources in app.experimental.main.
SUPPORTED_EXTERNAL_SOURCES = [
    SOURCE_NVD,
    SOURCE_JVN,
    SOURCE_EUVD,
    SOURCE_GHAD,
]

NVD_FEED_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
JVN_FEED_URL_TEMPLATE = "https://jvndb.jvn.jp/en/feed/detail/jvndb_detail_{year}.rdf"
CVE_PROJECT_ZIP_URL = "https://codeload.github.com/CVEProject/cvelistV5/zip/refs/heads/main"
GHAD_ZIP_URL = "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"

# Optional EUVD bulk-feed overrides. Leave them empty to use the live paginated API.
EUVD_BULK_JSON_URL = os.getenv("EUVD_BULK_JSON_URL", "").strip()
EUVD_BULK_NDJSON_URL = os.getenv("EUVD_BULK_NDJSON_URL", "").strip()
EUVD_BULK_CSV_URL = os.getenv("EUVD_BULK_CSV_URL", "").strip()

REQUEST_TIMEOUT = int(os.getenv("EXPERIMENTAL_REQUEST_TIMEOUT", "300"))
