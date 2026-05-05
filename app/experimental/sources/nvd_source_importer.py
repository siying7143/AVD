import json
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.experimental.config import NVD_FEED_URL_TEMPLATE, SOURCE_NVD
from app.experimental.sources.base import BaseSourceImporter
from app.experimental.utils import parse_date


def get_cvss_info(cve: Dict) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})
            return (
                cvss_data.get("baseScore"),
                metric.get("baseSeverity") or cvss_data.get("baseSeverity") or metric.get("severity"),
            )
    return None, None


def parse_cpe_criteria(criteria: str) -> Tuple[Optional[str], Optional[str]]:
    parts = criteria.split(":")
    if len(parts) < 5:
        return None, None
    vendor = parts[3] if parts[3] not in {"*", "-"} else None
    product = parts[4] if parts[4] not in {"*", "-"} else None
    return vendor, product


def walk_nodes_collect(nodes: List[Dict], vendors: Set[str], products: Set[str]) -> None:
    for node in nodes:
        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria")
            if not criteria:
                continue
            vendor, product = parse_cpe_criteria(criteria)
            if vendor:
                vendors.add(vendor)
            if product:
                products.add(product)
        walk_nodes_collect(node.get("nodes", []), vendors, products)


def get_all_vendors_products(cve: Dict) -> Tuple[List[str], List[str]]:
    vendors: Set[str] = set()
    products: Set[str] = set()
    for conf in cve.get("configurations", []):
        walk_nodes_collect(conf.get("nodes", []), vendors, products)
    return sorted(vendors), sorted(products)


class NVDSourceImporter(BaseSourceImporter):
    source_name = SOURCE_NVD

    def import_year(self, year: int) -> Iterable[Dict[str, object]]:
        # Normalize NVD feed rows into the same structure used by other experimental sources.
        payload = self.read_gzip_json(NVD_FEED_URL_TEMPLATE.format(year=year))
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            base_score, severity = get_cvss_info(cve)
            vendors, products = get_all_vendors_products(cve)
            references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

            yield self.normalize_record(
                source_record_id=cve_id,
                cve_id=cve_id,
                cve_year=year,
                published_date=parse_date(cve.get("published")),
                last_modified_date=parse_date(cve.get("lastModified")),
                severity=severity,
                base_score=base_score,
                vendor_names=vendors,
                product_names=products,
                references_json=references,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                raw_payload_json=json.dumps(item, ensure_ascii=False),
            )
