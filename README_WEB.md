# AVD Web Portal

This is a standalone, read-only web interface for published Australian Vulnerability Database records.

It does not replace or modify:

```bash
python -m app.main
python -m app.experimental.main
```

## Install

From the project root:

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-web.txt
```

## Run

Run from the project root, not from `app/web`:

```bash
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000
```


## Startup options

The web portal is started with Uvicorn:

```bash
python -m uvicorn app.web.main:app [OPTIONS]
```

Common startup options:

| Option | Example | Description |
| --- | --- | --- |
| `--reload` | `--reload` | Auto-restart when code changes. Use during development. |
| `--host` | `--host 127.0.0.1` | Bind address. Use `0.0.0.0` to accept connections from other devices. |
| `--port` | `--port 8000` | Server port. |
| `--workers` | `--workers 2` | Number of worker processes. Do not normally combine with `--reload`. |
| `--log-level` | `--log-level debug` | Log detail level. |
| `--env-file` | `--env-file .env` | Load environment variables from a specific file. |

Example commands:

```bash
python -m uvicorn app.web.main:app --reload --host 127.0.0.1 --port 8000
python -m uvicorn app.web.main:app --host 0.0.0.0 --port 8000 --workers 2 --log-level info
```

## Filter/query parameters

Both `/vulnerabilities` and `/api/vulnerabilities` accept these parameters: `q`, `cve`, `name`, `vendor`, `product`, `score_min`, `score_max`, `base_score_min`, `base_score_max`, `priority`, `severity`, `au_related`, `period`, `date_field`, `date_from`, `date_to`, `sort`, `page`, and `page_size`.

Example:

```text
http://127.0.0.1:8000/vulnerabilities?q=openssl&priority=critical&page_size=50
```

## What it reads

The UI reads the existing published AVD data from:

- `vulnerabilities`
- `avd_entries`
- `avd_assessments`

Only records where `avd_entries.record_status = 'published'` are displayed.

## Version 1.2 changes

- Reworked the homepage hero to avoid duplicated summary panels.
- Removed the OSV-like red line visual language and replaced it with a custom dark intelligence-map style.
- Renamed the product subtitle to Australian Vulnerability Database.
- Removed the score formula from the homepage.
- Kept the fixed top navigation with the current AVD navigation items.
- Retained scrollable filters, third-party references, clean date display, and score explanations on detail pages.
