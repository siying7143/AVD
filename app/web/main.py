from typing import List, Optional
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.web.repository import AVDRepository

# Base directory for web templates and static assets.
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="AVD Web Portal",
    description="Standalone read-only web UI for published AVD vulnerabilities.",
    version="1.2.0",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
repo = AVDRepository()


# Build a normalized filter dictionary used by list and pagination views.
def build_filters(
    q: Optional[str],
    cve: Optional[str],
    name: Optional[str],
    vendor: Optional[str],
    product: Optional[str],
    score_min: Optional[float],
    score_max: Optional[float],
    base_score_min: Optional[float],
    base_score_max: Optional[float],
    priority: List[str],
    severity: List[str],
    au_related: str,
    period: str,
    date_field: str,
    date_from: Optional[str],
    date_to: Optional[str],
    sort: str,
):
    return {
        "q": q,
        "cve": cve,
        "name": name,
        "vendor": vendor,
        "product": product,
        "score_min": score_min,
        "score_max": score_max,
        "base_score_min": base_score_min,
        "base_score_max": base_score_max,
        "priority": priority,
        "severity": severity,
        "au_related": au_related,
        "period": period,
        "date_field": date_field,
        "date_from": date_from,
        "date_to": date_to,
        "sort": sort,
    }


# Generate a URL while preserving the current non-empty query filters.
def query_url(path: str, current: dict, **updates) -> str:
    data = dict(current)
    data.update(updates)
    clean = []
    for key, value in data.items():
        if value in (None, "", [], ()):  # omit empty filters from links
            continue
        if isinstance(value, list):
            clean.extend((key, item) for item in value if item)
        else:
            clean.append((key, value))
    return f"{path}?{urlencode(clean)}" if clean else path


def fmt_number(value, digits=2):
    # Keep numeric display consistent across templates while gracefully handling missing values.
    if value in (None, ""):
        return "—"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def host_label(url: str):
    # Display a compact source host name instead of a full URL in link labels.
    if not url:
        return "Source"
    text = url.replace("https://", "").replace("http://", "")
    return text.split("/")[0]


templates.env.globals["query_url"] = query_url
templates.env.filters["fmt_number"] = fmt_number
templates.env.filters["host_label"] = host_label


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    # Load aggregate stats plus two curated record previews for the landing page.
    stats = repo.get_home_stats()
    preview = repo.list_vulnerabilities({"sort": "published_desc"}, page=1, page_size=6)
    high_signal = repo.list_vulnerabilities(
        {"sort": "score_desc", "priority": ["critical", "high"], "au_related": "yes"},
        page=1,
        page_size=4,
    )
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "stats": stats,
            "preview": preview["items"],
            "high_signal": high_signal["items"],
        },
    )


@app.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities(
    request: Request,
    q: Optional[str] = None,
    cve: Optional[str] = None,
    name: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    score_min: Optional[float] = Query(None, ge=0, le=10),
    score_max: Optional[float] = Query(None, ge=0, le=10),
    base_score_min: Optional[float] = Query(None, ge=0, le=10),
    base_score_max: Optional[float] = Query(None, ge=0, le=10),
    priority: List[str] = Query(default=[]),
    severity: List[str] = Query(default=[]),
    au_related: str = "all",
    period: str = "all",
    date_field: str = "published_at",
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort: str = "published_desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=5, le=100),
):
    # Render the searchable vulnerability list using validated query parameters
    # from the browser URL.
    filters = build_filters(
        q,
        cve,
        name,
        vendor,
        product,
        score_min,
        score_max,
        base_score_min,
        base_score_max,
        priority,
        severity,
        au_related,
        period,
        date_field,
        date_from,
        date_to,
        sort,
    )
    result = repo.list_vulnerabilities(filters, page=page, page_size=page_size)
    facets = repo.get_facets()
    query_state = {**filters, "page_size": page_size}
    return templates.TemplateResponse(
        "vulnerabilities.html",
        {
            "request": request,
            "items": result["items"],
            "total": result["total"],
            "page": result["page"],
            "pages": result["pages"],
            "page_size": result["page_size"],
            "filters": filters,
            "query_state": query_state,
            "facets": facets,
        },
    )


@app.get("/vulnerabilities/{cve_id}", response_class=HTMLResponse)
def vulnerability_detail(request: Request, cve_id: str):
    # Return a 404 instead of an empty page when a CVE is not published in AVD.
    item = repo.get_vulnerability_detail(cve_id)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return templates.TemplateResponse(
        "detail.html",
        {"request": request, "item": item},
    )


@app.get("/api/vulnerabilities")
def vulnerabilities_api(
    q: Optional[str] = None,
    cve: Optional[str] = None,
    name: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    score_min: Optional[float] = Query(None, ge=0, le=10),
    score_max: Optional[float] = Query(None, ge=0, le=10),
    base_score_min: Optional[float] = Query(None, ge=0, le=10),
    base_score_max: Optional[float] = Query(None, ge=0, le=10),
    priority: List[str] = Query(default=[]),
    severity: List[str] = Query(default=[]),
    au_related: str = "all",
    period: str = "all",
    date_field: str = "published_at",
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort: str = "published_desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=5, le=100),
):
    # Expose the same filtered list data as JSON for lightweight API consumers.
    filters = build_filters(
        q,
        cve,
        name,
        vendor,
        product,
        score_min,
        score_max,
        base_score_min,
        base_score_max,
        priority,
        severity,
        au_related,
        period,
        date_field,
        date_from,
        date_to,
        sort,
    )
    return repo.list_vulnerabilities(filters, page=page, page_size=page_size)
