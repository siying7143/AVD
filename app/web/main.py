from typing import List, Optional
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.web.repository import AVDRepository

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="AVD Web Portal",
    description="Read-only web UI for 2023-2026 Australian vulnerability intelligence with database search, detail reports and API docs.",
    version="2.0.0",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
repo = AVDRepository()

DATASET_YEARS = ["2023", "2024", "2025", "2026"]


def optional_score(value: Optional[str]):
    """Treat empty score inputs from HTML forms as omitted filters."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    if number < 0:
        return 0.0
    if number > 10:
        return 10.0
    return number


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
    year: List[str],
    au_related: str,
    kev: str,
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
        "year": year,
        "au_related": au_related,
        "kev": kev,
        "period": period,
        "date_field": date_field,
        "date_from": date_from,
        "date_to": date_to,
        "sort": sort,
    }


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
    if value in (None, ""):
        return "—"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def fmt_int(value):
    if value in (None, ""):
        return "0"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def host_label(url: str) -> str:
    if not url:
        return "Source"
    text = url.replace("https://", "").replace("http://", "")
    return text.split("/")[0]


templates.env.globals["query_url"] = query_url
templates.env.globals["dataset_years"] = DATASET_YEARS
templates.env.filters["fmt_number"] = fmt_number
templates.env.filters["fmt_int"] = fmt_int
templates.env.filters["host_label"] = host_label


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    stats = repo.get_home_stats()
    # Use CVE ID order on the landing page because some imported feeds share the same
    # publication timestamp. This keeps the preview visually current without inventing data.
    preview = repo.list_vulnerabilities({"sort": "cve_desc"}, page=1, page_size=6)
    high_signal = repo.list_vulnerabilities(
        {"sort": "score_desc", "priority": ["critical", "high"], "au_related": "yes"},
        page=1,
        page_size=5,
    )
    kev_queue = repo.list_vulnerabilities({"sort": "score_desc", "kev": "yes"}, page=1, page_size=5)
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "stats": stats,
            "preview": preview["items"],
            "high_signal": high_signal["items"],
            "kev_queue": kev_queue["items"],
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
    score_min: Optional[str] = None,
    score_max: Optional[str] = None,
    base_score_min: Optional[str] = None,
    base_score_max: Optional[str] = None,
    priority: List[str] = Query(default=[]),
    severity: List[str] = Query(default=[]),
    year: List[str] = Query(default=[]),
    au_related: str = "all",
    kev: str = "all",
    period: str = "all",
    date_field: str = "published_at",
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort: str = "published_desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=5, le=100),
):
    score_min = optional_score(score_min)
    score_max = optional_score(score_max)
    base_score_min = optional_score(base_score_min)
    base_score_max = optional_score(base_score_max)
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
        year,
        au_related,
        kev,
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
    item = repo.get_vulnerability_detail(cve_id)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return templates.TemplateResponse("detail.html", {"request": request, "item": item})



@app.get("/api", response_class=HTMLResponse)
def api_docs(request: Request):
    return templates.TemplateResponse("api.html", {"request": request})


@app.get("/api/vulnerabilities")
def vulnerabilities_api(
    q: Optional[str] = None,
    cve: Optional[str] = None,
    name: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    score_min: Optional[str] = None,
    score_max: Optional[str] = None,
    base_score_min: Optional[str] = None,
    base_score_max: Optional[str] = None,
    priority: List[str] = Query(default=[]),
    severity: List[str] = Query(default=[]),
    year: List[str] = Query(default=[]),
    au_related: str = "all",
    kev: str = "all",
    period: str = "all",
    date_field: str = "published_at",
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sort: str = "published_desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=5, le=100),
):
    score_min = optional_score(score_min)
    score_max = optional_score(score_max)
    base_score_min = optional_score(base_score_min)
    base_score_max = optional_score(base_score_max)
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
        year,
        au_related,
        kev,
        period,
        date_field,
        date_from,
        date_to,
        sort,
    )
    return repo.list_vulnerabilities(filters, page=page, page_size=page_size)


@app.get("/api/vulnerabilities/{cve_id}")
def vulnerability_detail_api(cve_id: str):
    item = repo.get_vulnerability_detail(cve_id)
    if not item:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return item
