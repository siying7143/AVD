import json
import math
from collections import Counter
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import pymysql

from app.config import (
    CISA_KEV_CATALOG_URL,
    DB_TABLE_AVD_ASSESSMENTS,
    DB_TABLE_AVD_ENTRIES,
    DB_TABLE_VULNERABILITIES,
)
from app.db import get_connection


DATASET_YEARS = [2023, 2024, 2025, 2026]

ALLOWED_SORTS = {
    "published_desc": "e.published_at DESC, v.cve_id DESC",
    "published_asc": "e.published_at ASC, v.cve_id ASC",
    "score_desc": "a.final_score DESC, v.base_score DESC, v.cve_id DESC",
    "score_asc": "a.final_score ASC, v.base_score ASC, v.cve_id ASC",
    "base_score_desc": "v.base_score DESC, v.cve_id DESC",
    "base_score_asc": "v.base_score ASC, v.cve_id ASC",
    "modified_desc": "v.last_modified_date DESC, v.cve_id DESC",
    "modified_asc": "v.last_modified_date ASC, v.cve_id ASC",
    "cve_desc": "v.cve_id DESC",
    "cve_asc": "v.cve_id ASC",
}

ALLOWED_DATE_FIELDS = {
    "published_at": "e.published_at",
    "assessed_at": "a.assessed_at",
    "nvd_published_date": "v.published_date",
    "last_modified_date": "v.last_modified_date",
}

PRIORITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _json_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x is not None and str(x).strip()]
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="ignore")
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(x) for x in parsed if x is not None and str(x).strip()]
    except json.JSONDecodeError:
        pass
    return [text]


def _format_temporal(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, date):
        return value.strftime("%Y-%m-%d")
    if value is None:
        return ""
    text = str(value)
    if "T" in text:
        text = text.replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    return text


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime, date)):
        return _format_temporal(value)
    return value


def _num(value: Any, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _display_score(value: Any) -> str:
    if value in (None, ""):
        return "—"
    try:
        return str(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except Exception:
        return str(value)


def _title_from_description(cve_id: str, description: str) -> str:
    desc = (description or "").strip()
    if not desc:
        return cve_id
    first_sentence = desc.split(".")[0].strip()
    title = first_sentence if first_sentence else desc
    return title[:170] + ("…" if len(title) > 170 else "")


def _dedupe_links(links: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    deduped = []
    for link in links:
        url = (link.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(link)
    return deduped


def _external_links(row: Dict[str, Any]) -> List[Dict[str, str]]:
    cve_id = row.get("cve_id")
    links: List[Dict[str, str]] = []
    if cve_id:
        links.append({"label": "NVD detail", "kind": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
        links.append({"label": "CVE.org record", "kind": "CVE", "url": f"https://www.cve.org/CVERecord?id={cve_id}"})
        links.append({"label": "FIRST EPSS lookup", "kind": "EPSS", "url": f"https://api.first.org/data/v1/epss?cve={cve_id}"})
        links.append({"label": "Cyber.gov.au search", "kind": "ACSC", "url": f"https://www.cyber.gov.au/search?keys={quote(str(cve_id))}"})
    if row.get("kev_status"):
        links.append({"label": "CISA KEV catalog", "kind": "KEV", "url": CISA_KEV_CATALOG_URL})
    if row.get("exploitation_risk_source_url"):
        source = row.get("exploitation_risk_source") or "Exploit source"
        links.append({"label": str(source), "kind": "Exploit", "url": row["exploitation_risk_source_url"]})
    if row.get("au_signal_source_url"):
        source = row.get("au_signal_label") or row.get("au_signal_source") or "AU source"
        links.append({"label": str(source), "kind": "AU", "url": row["au_signal_source_url"]})
    return _dedupe_links(links)


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    row = {k: _to_jsonable(v) for k, v in row.items()}

    row["vendors_list"] = _json_list(row.get("vendors"))
    row["products_list"] = _json_list(row.get("product_names"))
    row["cwe_list"] = _json_list(row.get("cwe_ids"))

    row["is_au_related"] = bool(
        row.get("au_signal_score") not in (None, 0, 0.0, "0", "0.0", "0.00", "")
        or row.get("au_signal_source")
        or row.get("au_signal_label")
        or row.get("au_signal_source_url")
    )

    desc = (row.get("description") or "").strip()
    row["title"] = _title_from_description(row.get("cve_id") or "", desc)
    row["summary"] = desc[:320] + ("…" if len(desc) > 320 else "")

    base = _num(row.get("base_score"))
    final = _num(row.get("final_score"))
    row["base_component"] = float((Decimal(str(base)) * Decimal("0.8")).quantize(Decimal("0.01")))
    row["score_pct"] = max(0, min(100, final * 10))
    row["base_score_display"] = _display_score(row.get("base_score"))
    row["final_score_display"] = _display_score(row.get("final_score"))
    row["exploit_score_display"] = _display_score(row.get("exploitation_risk_score"))
    row["au_score_display"] = _display_score(row.get("au_signal_score"))
    row["base_component_display"] = _display_score(row.get("base_component"))
    row["score_formula"] = (
        f"min(10.00, 0.8 × {row['base_score_display']} + "
        f"{row['exploit_score_display']} + {row['au_score_display']}) = {row['final_score_display']}"
    )
    row["external_links"] = _external_links(row)
    return row


def _where_from_filters(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    clauses = ["e.record_status = 'published'"]
    params: List[Any] = []

    q = (filters.get("q") or "").strip()
    if q:
        clauses.append(
            "(v.cve_id LIKE %s OR v.description LIKE %s OR v.vendors LIKE %s "
            "OR v.product_names LIKE %s OR v.cwe_ids LIKE %s)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like])

    cve = (filters.get("cve") or "").strip()
    if cve:
        clauses.append("v.cve_id LIKE %s")
        params.append(f"%{cve}%")

    name = (filters.get("name") or "").strip()
    if name:
        clauses.append("v.description LIKE %s")
        params.append(f"%{name}%")

    vendor = (filters.get("vendor") or "").strip()
    if vendor:
        clauses.append("v.vendors LIKE %s")
        params.append(f"%{vendor}%")

    product = (filters.get("product") or "").strip()
    if product:
        clauses.append("v.product_names LIKE %s")
        params.append(f"%{product}%")

    score_min = filters.get("score_min")
    if score_min not in (None, ""):
        clauses.append("a.final_score >= %s")
        params.append(score_min)

    score_max = filters.get("score_max")
    if score_max not in (None, ""):
        clauses.append("a.final_score <= %s")
        params.append(score_max)

    base_score_min = filters.get("base_score_min")
    if base_score_min not in (None, ""):
        clauses.append("v.base_score >= %s")
        params.append(base_score_min)

    base_score_max = filters.get("base_score_max")
    if base_score_max not in (None, ""):
        clauses.append("v.base_score <= %s")
        params.append(base_score_max)

    priorities = [p for p in filters.get("priority", []) if p]
    if priorities:
        placeholders = ", ".join(["%s"] * len(priorities))
        clauses.append(f"a.priority_level IN ({placeholders})")
        params.extend(priorities)

    severities = [s for s in filters.get("severity", []) if s]
    if severities:
        placeholders = ", ".join(["%s"] * len(severities))
        clauses.append(f"v.severity IN ({placeholders})")
        params.extend(severities)

    years = []
    for year in filters.get("year", []) or []:
        try:
            year_int = int(year)
        except (TypeError, ValueError):
            continue
        if year_int in DATASET_YEARS:
            years.append(year_int)
    if years:
        placeholders = ", ".join(["%s"] * len(years))
        clauses.append(f"YEAR(v.published_date) IN ({placeholders})")
        params.extend(years)

    au_related = filters.get("au_related")
    if au_related == "yes":
        clauses.append(
            "(COALESCE(a.au_signal_score, 0) > 0 OR a.au_signal_source IS NOT NULL "
            "OR a.au_signal_source_url IS NOT NULL)"
        )
    elif au_related == "no":
        clauses.append(
            "(COALESCE(a.au_signal_score, 0) = 0 AND a.au_signal_source IS NULL "
            "AND a.au_signal_source_url IS NULL)"
        )

    kev = filters.get("kev")
    if kev == "yes":
        clauses.append("a.kev_status = 1")
    elif kev == "no":
        clauses.append("(a.kev_status IS NULL OR a.kev_status = 0)")

    date_field_key = filters.get("date_field") or "published_at"
    date_column = ALLOWED_DATE_FIELDS.get(date_field_key, ALLOWED_DATE_FIELDS["published_at"])

    period = filters.get("period") or "all"
    if period in {"7d", "30d", "90d", "1y"}:
        days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}[period]
        clauses.append(f"{date_column} >= DATE_SUB(NOW(), INTERVAL {days} DAY)")

    date_from = filters.get("date_from")
    if date_from:
        clauses.append(f"{date_column} >= %s")
        params.append(date_from)

    date_to = filters.get("date_to")
    if date_to:
        clauses.append(f"{date_column} < DATE_ADD(%s, INTERVAL 1 DAY)")
        params.append(date_to)

    return " AND ".join(clauses), params


def _top_items(counter: Counter, limit: int = 8) -> List[Dict[str, Any]]:
    total = sum(counter.values()) or 1
    return [
        {"label": label, "count": count, "pct": round((count / total) * 100, 1)}
        for label, count in counter.most_common(limit)
    ]


class AVDRepository:
    def _connect(self):
        return get_connection()

    def get_home_stats(self) -> Dict[str, Any]:
        sql = f"""
        SELECT
            COUNT(*) AS total_published,
            SUM(CASE WHEN COALESCE(a.au_signal_score, 0) > 0 OR a.au_signal_source IS NOT NULL OR a.au_signal_source_url IS NOT NULL THEN 1 ELSE 0 END) AS au_related,
            SUM(CASE WHEN a.priority_level = 'critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN a.priority_level = 'high' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN a.kev_status = 1 THEN 1 ELSE 0 END) AS kev_count,
            AVG(a.final_score) AS avg_final_score,
            MAX(e.published_at) AS latest_published_at,
            MIN(v.published_date) AS earliest_nvd_published,
            MAX(v.published_date) AS latest_nvd_published
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE e.record_status = 'published' AND YEAR(v.published_date) BETWEEN 2023 AND 2026
        """
        with self._connect() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(sql)
                row = cursor.fetchone() or {}
        cleaned = {k: _to_jsonable(v) for k, v in row.items()}
        for key in ("total_published", "au_related", "critical_count", "high_count", "kev_count"):
            cleaned[key] = int(cleaned.get(key) or 0)
        return cleaned

    def get_facets(self) -> Dict[str, List[str]]:
        priority_sql = f"""
        SELECT DISTINCT a.priority_level
        FROM {DB_TABLE_AVD_ENTRIES} e
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE e.record_status = 'published' AND a.priority_level IS NOT NULL
        ORDER BY FIELD(a.priority_level, 'critical', 'high', 'medium', 'low'), a.priority_level
        """
        severity_sql = f"""
        SELECT DISTINCT v.severity
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        WHERE e.record_status = 'published' AND v.severity IS NOT NULL
        ORDER BY FIELD(v.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'), v.severity
        """
        with self._connect() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(priority_sql)
                priorities = [r["priority_level"] for r in cursor.fetchall() if r.get("priority_level")]
                cursor.execute(severity_sql)
                severities = [r["severity"] for r in cursor.fetchall() if r.get("severity")]
        return {
            "priorities": priorities or PRIORITY_ORDER,
            "severities": severities or SEVERITY_ORDER,
            "years": [str(y) for y in DATASET_YEARS],
        }

    def list_vulnerabilities(self, filters: Dict[str, Any], page: int, page_size: int) -> Dict[str, Any]:
        where_sql, params = _where_from_filters(filters)
        sort = ALLOWED_SORTS.get(filters.get("sort") or "published_desc", ALLOWED_SORTS["published_desc"])
        page = max(1, int(page or 1))
        page_size = max(5, min(100, int(page_size or 20)))
        offset = (page - 1) * page_size

        from_sql = f"""
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE {where_sql}
        """
        count_sql = f"SELECT COUNT(*) AS total {from_sql}"
        data_sql = f"""
        SELECT
            v.cve_id,
            v.description,
            v.base_score,
            v.severity,
            v.vendors,
            v.product_names,
            v.cwe_ids,
            v.published_date AS nvd_published_date,
            v.last_modified_date,
            e.created_at AS entry_created_at,
            e.updated_at AS entry_updated_at,
            e.published_at,
            a.exploitation_risk_score,
            a.exploitation_risk_source,
            a.exploitation_risk_source_url,
            a.kev_status,
            a.epss_score,
            a.epss_percentile,
            a.au_signal_score,
            a.au_signal_source,
            a.au_signal_source_url,
            a.au_signal_label,
            a.final_score,
            a.priority_level,
            a.assessed_at
        {from_sql}
        ORDER BY {sort}
        LIMIT %s OFFSET %s
        """

        with self._connect() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(count_sql, params)
                total = int((cursor.fetchone() or {}).get("total") or 0)
                cursor.execute(data_sql, params + [page_size, offset])
                items = [normalize_row(row) for row in cursor.fetchall()]

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, math.ceil(total / page_size)) if total else 1,
        }

    def get_vulnerability_detail(self, cve_id: str) -> Optional[Dict[str, Any]]:
        sql = f"""
        SELECT
            v.cve_id,
            v.description,
            v.base_score,
            v.severity,
            v.vendors,
            v.product_names,
            v.cwe_ids,
            v.published_date AS nvd_published_date,
            v.last_modified_date,
            e.created_at AS entry_created_at,
            e.updated_at AS entry_updated_at,
            e.published_at,
            a.base_score AS assessment_base_score,
            a.base_severity AS assessment_base_severity,
            a.exploitation_risk_score,
            a.exploitation_risk_source,
            a.exploitation_risk_source_url,
            a.kev_status,
            a.epss_score,
            a.epss_percentile,
            a.au_signal_score,
            a.au_signal_source,
            a.au_signal_source_url,
            a.au_signal_label,
            a.final_score,
            a.priority_level,
            a.assessed_at
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE e.record_status = 'published' AND v.cve_id = %s
        LIMIT 1
        """
        with self._connect() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(sql, (cve_id,))
                row = cursor.fetchone()
        return normalize_row(row) if row else None

    def get_analytics_data(self) -> Dict[str, Any]:
        summary = self.get_home_stats()

        by_year_sql = f"""
        SELECT
            YEAR(v.published_date) AS year,
            COUNT(*) AS total,
            SUM(CASE WHEN a.priority_level = 'critical' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN a.priority_level = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN COALESCE(a.au_signal_score, 0) > 0 OR a.au_signal_source IS NOT NULL OR a.au_signal_source_url IS NOT NULL THEN 1 ELSE 0 END) AS au_related,
            SUM(CASE WHEN a.kev_status = 1 THEN 1 ELSE 0 END) AS kev,
            AVG(a.final_score) AS avg_score
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE e.record_status = 'published' AND YEAR(v.published_date) BETWEEN 2023 AND 2026
        GROUP BY YEAR(v.published_date)
        ORDER BY year ASC
        """
        dist_sql = f"""
        SELECT
            COALESCE(a.priority_level, 'unscored') AS priority,
            COALESCE(v.severity, 'UNKNOWN') AS severity,
            COUNT(*) AS total
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        LEFT JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        WHERE e.record_status = 'published' AND YEAR(v.published_date) BETWEEN 2023 AND 2026
        GROUP BY COALESCE(a.priority_level, 'unscored'), COALESCE(v.severity, 'UNKNOWN')
        """
        raw_taxonomy_sql = f"""
        SELECT v.vendors, v.product_names, v.cwe_ids
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        WHERE e.record_status = 'published' AND YEAR(v.published_date) BETWEEN 2023 AND 2026
        """

        with self._connect() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(by_year_sql)
                by_year_rows = cursor.fetchall()
                cursor.execute(dist_sql)
                dist_rows = cursor.fetchall()
                cursor.execute(raw_taxonomy_sql)
                taxonomy_rows = cursor.fetchall()

        by_year_map: Dict[int, Dict[str, Any]] = {y: {"year": y, "total": 0, "critical": 0, "high": 0, "au_related": 0, "kev": 0, "avg_score": 0} for y in DATASET_YEARS}
        for row in by_year_rows:
            year = int(row.get("year") or 0)
            if year in by_year_map:
                by_year_map[year] = {
                    "year": year,
                    "total": int(row.get("total") or 0),
                    "critical": int(row.get("critical") or 0),
                    "high": int(row.get("high") or 0),
                    "au_related": int(row.get("au_related") or 0),
                    "kev": int(row.get("kev") or 0),
                    "avg_score": round(_num(row.get("avg_score")), 2),
                }
        by_year = list(by_year_map.values())
        max_year_total = max([r["total"] for r in by_year] or [1]) or 1
        for row in by_year:
            row["total_pct"] = round((row["total"] / max_year_total) * 100, 1)

        priority_counter: Counter = Counter()
        severity_counter: Counter = Counter()
        for row in dist_rows:
            priority_counter[str(row.get("priority") or "unscored")] += int(row.get("total") or 0)
            severity_counter[str(row.get("severity") or "UNKNOWN")] += int(row.get("total") or 0)

        vendor_counter: Counter = Counter()
        product_counter: Counter = Counter()
        cwe_counter: Counter = Counter()
        for row in taxonomy_rows:
            vendor_counter.update(_json_list(row.get("vendors")))
            product_counter.update(_json_list(row.get("product_names")))
            cwe_counter.update(_json_list(row.get("cwe_ids")))

        return {
            "summary": summary,
            "by_year": by_year,
            "priority_distribution": _top_items(priority_counter, limit=8),
            "severity_distribution": _top_items(severity_counter, limit=8),
            "top_vendors": _top_items(vendor_counter, limit=10),
            "top_products": _top_items(product_counter, limit=10),
            "top_cwe": _top_items(cwe_counter, limit=10),
        }
