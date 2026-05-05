import gzip
import json
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from datetime import datetime
from typing import Optional

import requests

from app.config import (
    BATCH_SIZE,
    DB_TABLE_VULNERABILITIES,
    NVD_FEED_URL_TEMPLATE,
    REQUEST_TIMEOUT,
)
from app.services.avd_pipeline_service import AVDPipelineService


# Convert optional NVD timestamp strings into Python datetime objects before
# inserting them into MySQL.
def to_datetime_or_none(dt_str: Optional[str]):
    if not dt_str:
        return None
    text = str(dt_str).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


# Prefer the English NVD description because the AVD UI and downstream
# scoring logic expect human-readable English text.
def get_english_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return (item.get("value") or "").strip()
    if descriptions:
        return (descriptions[0].get("value") or "").strip()
    return ""


# Extract the strongest available CVSS signal, trying v3.1, then v3.0, then
# v2 so older records can still be scored.
def get_cvss_info(cve: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(key, [])
        if metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})

            base_score = cvss_data.get("baseScore")
            severity = (
                metric.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or metric.get("severity")
            )
            return base_score, severity

    return None, None


def get_all_cwe_ids(cve: Dict[str, Any]) -> List[str]:
    result: Set[str] = set()

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                result.add(value)

    return sorted(result)


def parse_cpe_criteria(criteria: str) -> Tuple[Optional[str], Optional[str]]:
    parts = criteria.split(":")
    if len(parts) >= 5:
        vendor = parts[3] if parts[3] not in ("*", "-") else None
        product = parts[4] if parts[4] not in ("*", "-") else None
        return vendor, product
    return None, None


# Recursively walk NVD configuration nodes to collect vendor/product CPE data
# from nested match criteria.
def walk_nodes_collect(
    nodes: List[Dict[str, Any]],
    vendors: Set[str],
    products: Set[str]
) -> None:
    for node in nodes:
        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria")
            if criteria:
                vendor, product = parse_cpe_criteria(criteria)
                if vendor:
                    vendors.add(vendor)
                if product:
                    products.add(product)

        child_nodes = node.get("nodes", [])
        if child_nodes:
            walk_nodes_collect(child_nodes, vendors, products)


def get_all_vendors_products(cve: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    vendors: Set[str] = set()
    products: Set[str] = set()

    for conf in cve.get("configurations", []):
        nodes = conf.get("nodes", [])
        walk_nodes_collect(nodes, vendors, products)

    return sorted(vendors), sorted(products)


# Flatten one raw NVD vulnerability item into the database column order used by
# insert_batch().
def build_row(vuln_item: Dict[str, Any]) -> Tuple[Any, ...]:
    cve = vuln_item.get("cve", {})

    cve_id = cve.get("id")
    description = get_english_description(cve)
    base_score, severity = get_cvss_info(cve)
    vendors, product_names = get_all_vendors_products(cve)
    cwe_ids = get_all_cwe_ids(cve)
    published_date = to_datetime_or_none(cve.get("published"))
    last_modified_date = to_datetime_or_none(cve.get("lastModified"))

    return (
        cve_id,
        description,
        base_score,
        severity,
        json.dumps(vendors, ensure_ascii=False),
        json.dumps(product_names, ensure_ascii=False),
        json.dumps(cwe_ids, ensure_ascii=False),
        published_date,
        last_modified_date,
    )


class NVDImporter:
    def __init__(self, connection):
        self.connection = connection
        self.pipeline_service = AVDPipelineService(connection)

    def download_feed(self, year: int) -> Dict[str, Any]:
        # NVD publishes one compressed JSON feed per year; download and decode it
        # before row normalization.
        url = NVD_FEED_URL_TEMPLATE.format(year=year)
        print(f"[INFO] Downloading feed: {url}")

        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        with gzip.GzipFile(fileobj=BytesIO(response.content)) as gz:
            data = json.load(gz)

        return data

    def insert_batch(self, rows: List[Tuple[Any, ...]]) -> None:
        # Use an upsert so re-running the importer refreshes changed CVEs without
        # duplicating existing records.
        sql = f"""
        INSERT INTO {DB_TABLE_VULNERABILITIES} (
            cve_id,
            description,
            base_score,
            severity,
            vendors,
            product_names,
            cwe_ids,
            published_date,
            last_modified_date
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON DUPLICATE KEY UPDATE
            description = VALUES(description),
            base_score = VALUES(base_score),
            severity = VALUES(severity),
            vendors = VALUES(vendors),
            product_names = VALUES(product_names),
            cwe_ids = VALUES(cwe_ids),
            published_date = VALUES(published_date),
            last_modified_date = VALUES(last_modified_date)
        """

        with self.connection.cursor() as cursor:
            cursor.executemany(sql, rows)

    def chunked(self, rows: Iterable[Tuple[Any, ...]], size: int):
        batch = []
        for row in rows:
            batch.append(row)
            if len(batch) >= size:
                yield batch
                batch = []
        if batch:
            yield batch

    def get_existing_map(self, cve_ids: List[str]) -> Dict[str, Tuple[Any, ...]]:
        if not cve_ids:
            return {}

        placeholders = ", ".join(["%s"] * len(cve_ids))
        sql = f"""
        SELECT
            cve_id,
            description,
            base_score,
            severity,
            vendors,
            product_names,
            cwe_ids,
            published_date,
            last_modified_date
        FROM {DB_TABLE_VULNERABILITIES}
        WHERE cve_id IN ({placeholders})
        """

        with self.connection.cursor() as cursor:
            cursor.execute(sql, cve_ids)
            rows = cursor.fetchall()

        result = {}
        for row in rows:
            result[row[0]] = row
        return result

    def get_changed_cve_ids(self, batch: List[Tuple[Any, ...]]) -> List[str]:
        # Compare timestamps and core fields against the existing table so the
        # AVD pipeline only recalculates entries that changed.
        cve_ids = [row[0] for row in batch]
        existing_map = self.get_existing_map(cve_ids)

        changed_ids = []
        for row in batch:
            cve_id = row[0]
            existing = existing_map.get(cve_id)

            if existing is None:
                changed_ids.append(cve_id)
                continue

            if tuple(existing) != tuple(row):
                changed_ids.append(cve_id)

        return changed_ids

    def import_year(self, year: int) -> None:
        # Process one year in batches: normalize feed rows, detect changes, upsert
        # source data, then publish/update affected AVD entries.
        data = self.download_feed(year)
        vulns = data.get("vulnerabilities", [])
        print(f"[INFO] {year}: fetched {len(vulns)} records")

        valid_rows = []
        for item in vulns:
            row = build_row(item)
            if row[0]:
                valid_rows.append(row)

        processed = 0
        affected_total = 0

        for batch in self.chunked(valid_rows, BATCH_SIZE):
            changed_cve_ids = self.get_changed_cve_ids(batch)

            self.insert_batch(batch)

            if changed_cve_ids:
                self.pipeline_service.process_cve_ids(changed_cve_ids)
                affected_total += len(changed_cve_ids)

            self.connection.commit()
            processed += len(batch)
            print(
                f"[INFO] {year}: inserted/updated {processed}/{len(valid_rows)}, "
                f"changed_for_avd={affected_total}"
            )

        print(f"[INFO] {year}: import completed")

    def import_years(self, years: List[int]) -> None:
        for year in years:
            try:
                self.import_year(year)
            except Exception:
                self.connection.rollback()
                raise