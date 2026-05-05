# Australian Vulnerability Database (AVD)

This project imports vulnerability records from external sources, enriches the data, stores it in a MySQL database, and provides a read-only FastAPI web portal for browsing published AVD records.

## Requirements

- Python 3.10 or later
- MySQL 8.0 or later
- Internet access for downloading vulnerability feeds
- A terminal running from the project root directory

## 1. Create and activate a virtual environment

From the project root:

```bash
python -m venv .venv
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

## 2. Install dependencies

Install the core import pipeline dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install the web portal dependencies:

```bash
python -m pip install -r requirements-web.txt
```

## 3. Configure environment variables

Create or update the `.env` file in the project root. The project already includes a sample-style `.env` file with the expected keys.

```env
DB_HOST=
DB_PORT=
DB_USER=
DB_PASSWORD=
DB_NAME=avd
DB_TABLE_VULNERABILITIES=vulnerabilities
DB_TABLE_AVD_ENTRIES=avd_entries
DB_TABLE_AVD_ASSESSMENTS=avd_assessments
DB_TABLE_EXPERIMENTAL_SOURCE_RECORDS=experimental_source_records
DB_TABLE_EXPERIMENTAL_METRICS=experimental_metrics
EXPERIMENTAL_REQUEST_TIMEOUT=300
EUVD_BULK_JSON_URL=
EUVD_BULK_NDJSON_URL=
EUVD_BULK_CSV_URL=
```

Update the database host, user, password, and database name to match your local MySQL setup.

### Environment variable reference

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `DB_HOST` | No | `127.0.0.1` | MySQL server hostname or IP address. |
| `DB_PORT` | No | `3306` | MySQL server port. |
| `DB_USER` | No | `root` | MySQL username. |
| `DB_PASSWORD` | No | Empty string | MySQL password. |
| `DB_NAME` | No | `avd` | Target database name. |
| `DB_TABLE_VULNERABILITIES` | No | `vulnerabilities` | Core NVD vulnerability table. |
| `DB_TABLE_AVD_ENTRIES` | No | `avd_entries` | Published/draft AVD entry table. |
| `DB_TABLE_AVD_ASSESSMENTS` | No | `avd_assessments` | AVD assessment table. |
| `DB_TABLE_EXPERIMENTAL_SOURCE_RECORDS` | No | `experimental_source_records` | Experimental normalized source-record table. |
| `DB_TABLE_EXPERIMENTAL_METRICS` | No | `experimental_metrics` | Experimental metric-output table. |
| `EXPERIMENTAL_REQUEST_TIMEOUT` | No | `300` | Timeout in seconds for experimental source HTTP requests. |
| `EUVD_BULK_JSON_URL` | No | Empty string | Optional EUVD bulk JSON feed URL. |
| `EUVD_BULK_NDJSON_URL` | No | Empty string | Optional EUVD bulk NDJSON feed URL. |
| `EUVD_BULK_CSV_URL` | No | Empty string | Optional EUVD bulk CSV feed URL. |

## 4. Prepare the database

Create the target database before running the import scripts:

```sql
CREATE DATABASE IF NOT EXISTS avd CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

If you are running the experimental pipeline, also apply the experimental schema:

```bash
mysql -u root -p avd < app/experimental/db_schema.sql
```

The experimental runner also calls `SchemaService.ensure_schema(...)`, so missing experimental tables are created automatically when the runner starts. Applying the SQL file manually is still useful for checking database access before a long import.

## 5. Run the main import pipeline

Run this command from the project root:

```bash
python -m app.main
```

The main pipeline imports NVD vulnerability data for the years configured in `app/config.py`:

```python
DEFAULT_YEARS = [2026, 2025, 2024, 2023]
```

### Main pipeline startup options

`app.main` does not currently expose command-line flags. To change its startup behavior, edit these settings in `app/config.py` or `.env`:

| Setting | Where | Description |
| --- | --- | --- |
| `DEFAULT_YEARS` | `app/config.py` | CVE publication years imported by `python -m app.main`. |
| `BATCH_SIZE` | `app/config.py` | Number of rows processed per database batch. |
| `REQUEST_TIMEOUT` | `app/config.py` | HTTP timeout for NVD and enrichment requests. |
| `DB_*` values | `.env` | Database connection and table-name settings. |

Example: import only 2025 records by changing `DEFAULT_YEARS` to:

```python
DEFAULT_YEARS = [2025]
```

## 6. Run the experimental pipeline

Default command:

```bash
python -m app.experimental.main
```

This imports the default scenario years and external sources, then calculates comparison metrics.

### Experimental pipeline startup options

```bash
python -m app.experimental.main [--years YEARS ...] [--sources SOURCE ...] [--skip-import]
```

| Option | Required | Default | Allowed values | Description |
| --- | --- | --- | --- | --- |
| `--years YEARS ...` | No | `2023 2024 2025` | One or more integer years | Scenario CVE years to import and calculate. |
| `--sources SOURCE ...` | No | `NVD JVN EUVD GHAD` | `NVD`, `JVN`, `EUVD`, `GHAD` | External sources to import before metric calculation. |
| `--skip-import` | No | Disabled | Flag only | Skip downloading/importing source records and recalculate metrics from existing MySQL data. |

Examples:

```bash
# Run the default experiment.
python -m app.experimental.main

# Recalculate metrics for 2024 only, using source records already in MySQL.
python -m app.experimental.main --years 2024 --skip-import

# Import and compare only NVD and GHAD for 2023 and 2024.
python -m app.experimental.main --years 2023 2024 --sources NVD GHAD

# Import JVN and EUVD for 2025, then calculate metrics.
python -m app.experimental.main --years 2025 --sources JVN EUVD
```

## 7. Run the web portal

Start the FastAPI development server from the project root:

```bash
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8000
```

Open the web portal in a browser:

```text
http://127.0.0.1:8000
```

### Web server startup options

The web portal is started through `uvicorn`, so the most useful startup parameters are Uvicorn options:

```bash
python -m uvicorn app.web.main:app [OPTIONS]
```

| Option | Example | Description |
| --- | --- | --- |
| `--reload` | `--reload` | Restart the server automatically when code changes. Useful during development. |
| `--host` | `--host 127.0.0.1` | Host/IP address to bind. Use `0.0.0.0` to accept external connections. |
| `--port` | `--port 8000` | Port used by the web server. |
| `--workers` | `--workers 2` | Number of worker processes. Do not combine with `--reload` for normal development. |
| `--log-level` | `--log-level debug` | Logging detail level, such as `debug`, `info`, `warning`, or `error`. |
| `--env-file` | `--env-file .env` | Load environment variables from a specific env file. |

Examples:

```bash
# Development mode on localhost.
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8000

# Run on another local port.
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8080

# Allow access from other devices on the same network.
python -m uvicorn app.web.main:app --host 0.0.0.0 --port 8000

# Production-style multi-worker run without reload.
python -m uvicorn app.web.main:app --host 0.0.0.0 --port 8000 --workers 2 --log-level info
```

### Web query parameters

The list page and JSON API accept the same filtering parameters:

```text
/vulnerabilities
/api/vulnerabilities
```

| Query parameter | Example | Description |
| --- | --- | --- |
| `q` | `?q=openssl` | General keyword search. |
| `cve` | `?cve=CVE-2025` | CVE ID or partial CVE search. |
| `name` | `?name=buffer` | Title/name search. |
| `vendor` | `?vendor=microsoft` | Filter by affected vendor. |
| `product` | `?product=windows` | Filter by affected product. |
| `score_min` / `score_max` | `?score_min=7&score_max=10` | Filter by final AVD score range. |
| `base_score_min` / `base_score_max` | `?base_score_min=5` | Filter by source CVSS/base score range. |
| `priority` | `?priority=critical&priority=high` | Filter by one or more AVD priority levels. |
| `severity` | `?severity=CRITICAL` | Filter by one or more source severity levels. |
| `au_related` | `?au_related=yes` | Filter Australian-relevance signal. Common values: `all`, `yes`, `no`. |
| `period` | `?period=30d` | Filter by a predefined date period if supported by the repository logic. |
| `date_field` | `?date_field=published_at` | Select the date field used with date filters. |
| `date_from` / `date_to` | `?date_from=2025-01-01&date_to=2025-12-31` | Filter by explicit date range. |
| `sort` | `?sort=score_desc` | Sort order. Common values include `published_desc`, `score_desc`, `score_asc`, `base_score_desc`, and `base_score_asc`. |
| `page` | `?page=2` | Result page number. |
| `page_size` | `?page_size=50` | Results per page. Allowed range is 5 to 100. |

Examples:

```text
http://127.0.0.1:8000/vulnerabilities?q=openssl&priority=critical&page_size=50
http://127.0.0.1:8000/api/vulnerabilities?au_related=yes&sort=score_desc&page=1
```

## Useful commands

```bash
# Run the core importer.
python -m app.main

# Run the default experimental importer and metrics calculator.
python -m app.experimental.main

# Recalculate experimental metrics without importing source data again.
python -m app.experimental.main --skip-import

# Run the web UI.
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8000
```

## Project structure

```text
app/
  config.py                         # Core application and database settings.
  db.py                             # Database connection helper.
  main.py                           # Main NVD import entry point.
  importers/                        # Core source importers.
  services/                         # Core enrichment and assessment services.
  experimental/                     # Experimental source import and metrics pipeline.
  web/                              # FastAPI web portal, templates, and static files.
requirements.txt                    # Core Python dependencies.
requirements-web.txt                # Web portal dependencies.
README_WEB.md                       # Additional notes for the web portal.
```

## Notes

- Run all Python module commands from the project root so imports resolve correctly.
- The web portal is read-only and displays records that are already stored in the database.
- Feed imports may take time because they download and process external vulnerability data.
- Keep real production credentials out of version control.
