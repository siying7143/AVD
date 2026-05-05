import json
import math
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.experimental.config import GHAD_ZIP_URL, SOURCE_GHAD
from app.experimental.sources.base import BaseSourceImporter
from app.experimental.utils import extract_cve_year, parse_date


def collect_packages(advisory: Dict) -> Tuple[List[str], List[str]]:
    ecosystems: Set[str] = set()
    packages: Set[str] = set()
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if ecosystem:
            ecosystems.add(str(ecosystem))
        if name:
            packages.add(str(name))
    return sorted(ecosystems), sorted(packages)


def collect_alias_cves(advisory: Dict) -> List[str]:
    aliases = advisory.get("aliases", [])
    return sorted(
        {
            str(alias).upper()
            for alias in aliases
            if str(alias).upper().startswith("CVE-")
        }
    )


def extract_numeric_score(value) -> Optional[float]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        number = float(value)
        return number if 0.0 <= number <= 10.0 else None

    if isinstance(value, str):
        text = value.strip()
        try:
            number = float(text)
            return number if 0.0 <= number <= 10.0 else None
        except ValueError:
            return None

    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score"):
            if key in value:
                number = extract_numeric_score(value[key])
                if number is not None:
                    return number

    return None


def normalize_severity(advisory: Dict) -> Optional[str]:
    ds = advisory.get("database_specific", {}) or {}
    candidate = ds.get("severity", advisory.get("severity"))

    if isinstance(candidate, str):
        return candidate[:255]

    if isinstance(candidate, list):
        parts = []
        for item in candidate:
            if isinstance(item, dict):
                score = item.get("score")
                item_type = item.get("type")
                if item_type and score:
                    parts.append(f"{item_type}:{score}")
                elif score:
                    parts.append(str(score))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
            else:
                parts.append(str(item))
        text = "; ".join(p for p in parts if p).strip()
        return text[:255] if text else None

    if isinstance(candidate, dict):
        text = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
        return text[:255]

    return str(candidate)[:255] if candidate is not None else None


CVSS_VECTOR_RE = re.compile(r"(CVSS:3\.[01]/[A-Z]{1,4}:[^ \t\r\n;]+)")
CVSS_V2_VECTOR_RE = re.compile(r"((?:AV|AC|Au|C|I|A):[^ \t\r\n;]+(?:/[A-Za-z]{1,3}:[^ \t\r\n;]+)+)")


def round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10.0 - 1e-9) / 10.0


def parse_cvss_vector_string(value) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, dict):
        for key in ("vectorString", "vector", "score"):
            vector = parse_cvss_vector_string(value.get(key))
            if vector:
                return vector
        return None

    if isinstance(value, str):
        text = value.strip()

        m = CVSS_VECTOR_RE.search(text)
        if m:
            return m.group(1)

        if text.startswith("AV:") or "/AV:" in text or text.startswith("AC:"):
            m2 = CVSS_V2_VECTOR_RE.search(text)
            if m2:
                return m2.group(1)

    return None


def _parse_vector_components(vector: str) -> Dict[str, str]:
    parts = vector.strip().split("/")
    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def calculate_cvss_v3_base_score(vector: str) -> Optional[float]:
    metrics = _parse_vector_components(vector)
    if "CVSS" not in metrics:
        return None

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_u_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c_map = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_map = {"N": 0.85, "R": 0.62}
    cia_map = {"N": 0.00, "L": 0.22, "H": 0.56}

    try:
        av = av_map[metrics["AV"]]
        ac = ac_map[metrics["AC"]]
        scope = metrics["S"]
        ui = ui_map[metrics["UI"]]
        c = cia_map[metrics["C"]]
        i = cia_map[metrics["I"]]
        a = cia_map[metrics["A"]]
        pr = pr_c_map[metrics["PR"]] if scope == "C" else pr_u_map[metrics["PR"]]
    except KeyError:
        return None

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0

    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return round_up_1_decimal(base)


def calculate_cvss_v2_base_score(vector: str) -> Optional[float]:
    metrics = _parse_vector_components(vector)

    av_map = {"L": 0.395, "A": 0.646, "N": 1.000}
    ac_map = {"H": 0.35, "M": 0.61, "L": 0.71}
    au_map = {"M": 0.45, "S": 0.56, "N": 0.704}
    cia_map = {"N": 0.0, "P": 0.275, "C": 0.660}

    try:
        av = av_map[metrics["AV"]]
        ac = ac_map[metrics["AC"]]
        au = au_map[metrics["Au"]]
        c = cia_map[metrics["C"]]
        i = cia_map[metrics["I"]]
        a = cia_map[metrics["A"]]
    except KeyError:
        return None

    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20.0 * av * ac * au

    if impact == 0:
        f_impact = 0.0
    else:
        f_impact = 1.176

    base = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    base = max(0.0, min(base, 10.0))
    return round(base, 1)


def calculate_cvss_base_score_from_vector(vector: str) -> Optional[float]:
    if not vector:
        return None
    vector = vector.strip()

    if vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/"):
        return calculate_cvss_v3_base_score(vector)

    if vector.startswith("AV:") or "/Au:" in vector:
        return calculate_cvss_v2_base_score(vector)

    return None


# Extract the most reliable GHSA CVSS base score from structured fields,
# vectors, severity arrays, or fallback database-specific content.
def extract_ghad_base_score(advisory: Dict) -> Optional[float]:
    database_specific = advisory.get("database_specific", {}) or {}

    # 1) database_specific.cvss numeric/dict
    number = extract_numeric_score(database_specific.get("cvss"))
    if number is not None:
        return number

    # 2) database_specific.cvss vector
    vector = parse_cvss_vector_string(database_specific.get("cvss"))
    if vector:
        score = calculate_cvss_base_score_from_vector(vector)
        if score is not None:
            return score

    # 3) severity[] entries
    for item in advisory.get("severity", []) or []:
        if not isinstance(item, dict):
            continue

        number = extract_numeric_score(item.get("score"))
        if number is not None:
            return number

        vector = parse_cvss_vector_string(item.get("score"))
        if vector:
            score = calculate_cvss_base_score_from_vector(vector)
            if score is not None:
                return score

    # 4) some advisories may expose cvss-ish content elsewhere in database_specific
    for key in ("severity", "cvss_v3", "cvss_v2"):
        vector = parse_cvss_vector_string(database_specific.get(key))
        if vector:
            score = calculate_cvss_base_score_from_vector(vector)
            if score is not None:
                return score

    return None


class GHADSourceImporter(BaseSourceImporter):
    source_name = SOURCE_GHAD

    def import_year(self, year: int) -> Iterable[Dict[str, object]]:
        # Iterate the GitHub Advisory Database archive and emit CVE-linked advisories
        # whose publication year matches the requested scenario.
        for filename, raw in self.iter_zip_members(GHAD_ZIP_URL, (".json",)):
            normalized = filename.replace("\\", "/")
            if "/advisories/" not in normalized:
                continue

            advisory = json.loads(raw.decode("utf-8", errors="replace"))
            cve_ids = collect_alias_cves(advisory)
            if not cve_ids:
                continue

            severity = normalize_severity(advisory)
            published_date = parse_date(advisory.get("published"))
            modified_date = parse_date(advisory.get("modified"))
            ecosystems, packages = collect_packages(advisory)
            references = [
                ref.get("url")
                for ref in advisory.get("references", [])
                if ref.get("url")
            ]

            base_score = extract_ghad_base_score(advisory)
            database_specific = advisory.get("database_specific", {}) or {}

            for cve_id in cve_ids:
                cve_year = extract_cve_year(cve_id)
                if cve_year != year:
                    continue

                if base_score is None:
                    print(
                        f"[DEBUG] GHAD {year} no score: "
                        f"id={advisory.get('id')} "
                        f"cve={cve_id} "
                        f"severity={advisory.get('severity')} "
                        f"db_cvss={database_specific.get('cvss')}",
                        flush=True,
                    )

                yield self.normalize_record(
                    source_record_id=f"{advisory.get('id', filename)}::{cve_id}",
                    cve_id=cve_id,
                    cve_year=year,
                    published_date=published_date,
                    last_modified_date=modified_date,
                    severity=severity,
                    base_score=base_score,
                    vendor_names=ecosystems,
                    product_names=packages,
                    references_json=references,
                    source_url=(
                        f"https://github.com/advisories/{advisory.get('id')}"
                        if advisory.get("id")
                        else None
                    ),
                    raw_payload_json=json.dumps(advisory, ensure_ascii=False),
                )