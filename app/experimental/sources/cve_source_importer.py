import json
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.experimental.config import CVE_PROJECT_ZIP_URL, SOURCE_CVE
from app.experimental.sources.base import BaseSourceImporter
from app.experimental.utils import extract_cve_year, parse_date


def collect_cna_affected_products(containers: Dict) -> Tuple[List[str], List[str]]:
    vendors: Set[str] = set()
    products: Set[str] = set()

    for affected in containers.get("cna", {}).get("affected", []):
        vendor = affected.get("vendor")
        product = affected.get("product")
        if vendor and vendor not in {"n/a", "unknown"}:
            vendors.add(vendor)
        if product and product not in {"n/a", "unknown"}:
            products.add(product)
    return sorted(vendors), sorted(products)


def collect_references(containers: Dict) -> List[str]:
    refs = []
    for ref in containers.get("cna", {}).get("references", []):
        url = ref.get("url")
        if url:
            refs.append(url)
    return refs


def get_cna_score(cna_metrics: List[Dict]) -> Tuple[Optional[float], Optional[str]]:
    for metric in cna_metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            payload = metric.get(key)
            if payload:
                return payload.get("baseScore"), payload.get("baseSeverity")
    return None, None


class CVESourceImporter(BaseSourceImporter):
    source_name = SOURCE_CVE

    def import_year(self, year: int) -> Iterable[Dict[str, object]]:
        # Read CVEProject JSON files from the main branch archive and keep records
        # whose CVE year matches the requested scenario.
        year_fragment = f"/cves/{year}/"
        for filename, raw in self.iter_zip_members(CVE_PROJECT_ZIP_URL, (".json",)):
            normalized_name = filename.replace("\\", "/")
            if year_fragment not in normalized_name:
                continue

            payload = json.loads(raw.decode("utf-8", errors="replace"))
            metadata = payload.get("cveMetadata", {})
            cve_id = metadata.get("cveId")
            cve_year = extract_cve_year(cve_id or "")
            if not cve_id or cve_year != year:
                continue

            containers = payload.get("containers", {})
            vendors, products = collect_cna_affected_products(containers)
            base_score, severity = get_cna_score(containers.get("cna", {}).get("metrics", []))

            yield self.normalize_record(
                source_record_id=cve_id,
                cve_id=cve_id,
                cve_year=year,
                published_date=parse_date(metadata.get("datePublished")),
                last_modified_date=parse_date(metadata.get("dateUpdated")),
                severity=severity,
                base_score=base_score,
                vendor_names=vendors,
                product_names=products,
                references_json=collect_references(containers),
                source_url=f"https://www.cve.org/CVERecord?id={cve_id}",
                raw_payload_json=json.dumps(payload, ensure_ascii=False),
            )
