import json
import re
from datetime import date, datetime
from typing import Any, Iterable, Optional
from urllib.parse import urlparse


CVE_ID_PATTERN = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)


def extract_cve_ids(text: Optional[str]) -> list[str]:
    if not text:
        return []
    return sorted({match.group(0).upper() for match in CVE_ID_PATTERN.finditer(text)})


def extract_cve_year(cve_id: str) -> Optional[int]:
    match = CVE_ID_PATTERN.search(cve_id or "")
    return int(match.group(1)) if match else None


def parse_date(value: Any) -> Optional[date]:
    if value in (None, "", "null"):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()

    text = str(value).strip()
    if not text:
        return None

    text = text.replace("Z", "+00:00")
    for candidate in (text[:10], text):
        try:
            if len(candidate) == 10:
                return datetime.strptime(candidate, "%Y-%m-%d").date()
            return datetime.fromisoformat(candidate).date()
        except ValueError:
            continue
    return None


def to_json_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def from_json_text(value: Any, default: Any):
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def safe_divide(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def percentage(numerator: float, denominator: float) -> float:
    return safe_divide(numerator, denominator) * 100.0


def average(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)


def valid_url(value: Optional[str]) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
