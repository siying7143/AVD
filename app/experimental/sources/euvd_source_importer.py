import json
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set

from app.experimental.config import SOURCE_EUVD
from app.experimental.sources.base import BaseSourceImporter
from app.experimental.utils import extract_cve_ids, extract_cve_year, parse_date, valid_url


class EUVDSourceImporter(BaseSourceImporter):
    source_name = SOURCE_EUVD

    SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/search"
    PAGE_SIZE = 100

    @staticmethod
    def _log(message: str) -> None:
        print(message, flush=True)

    def import_year(self, year: int) -> Iterable[Dict[str, object]]:
        # Use bulk feeds when configured; otherwise fall back to the paginated EUVD API.
        page = 0
        emitted: Set[str] = set()
        pages_seen = 0
        parse_fail_logged = 0
        self._log(f"[INFO] EUVD {year}: import started")

        while True:
            params = {
                "fromDate": f"{year}-01-01",
                "toDate": f"{year}-12-31",
                "fromScore": 0,
                "toScore": 10,
                "page": page,
                "size": self.PAGE_SIZE,
            }
            payload = self.get_json(f"{self.SEARCH_URL}?" + self._to_query(params))
            items = self._extract_items(payload)
            pages_seen += 1
            self._log(f"[INFO] EUVD {year}: page={page + 1} items={len(items)} emitted_total={len(emitted)}")
            if not items:
                break

            for item in items:
                cve_ids = self._extract_cve_ids_from_item(item)
                cve_ids = [c for c in cve_ids if extract_cve_year(c) == year]
                if not cve_ids:
                    continue

                raw_published = self._pick_first(
                    item,
                    ["datePublished", "published", "publishedDate", "publicationDate", "createdAt"],
                )
                raw_modified = self._pick_first(
                    item,
                    ["dateUpdated", "updated", "lastModified", "modifiedDate", "updatedAt"],
                )

                published = self._parse_euvd_datetime(raw_published)
                modified = self._parse_euvd_datetime(raw_modified)

                if published is None and raw_published not in (None, "") and parse_fail_logged < 5:
                    self._log(
                        f"[WARN] EUVD {year}: could not parse published date: {raw_published!r} "
                        f"for id={item.get('id') or item.get('euvdId') or item.get('enisaUuid')}"
                    )
                    parse_fail_logged += 1

                base_score = self._extract_base_score(item)
                severity = self._extract_severity(item)
                vendors = sorted(self._extract_named_values(item, ["vendor", "vendors"]))
                products = sorted(self._extract_named_values(item, ["product", "products"]))
                refs = self._extract_references(item)
                source_id = self._extract_source_id(item, cve_ids)
                source_url = self._extract_source_url(item, cve_ids, source_id)

                for cve_id in cve_ids:
                    record_id = f"{source_id}::{cve_id}"
                    if record_id in emitted:
                        continue
                    emitted.add(record_id)
                    yield self.normalize_record(
                        source_record_id=record_id,
                        cve_id=cve_id,
                        cve_year=year,
                        published_date=published,
                        last_modified_date=modified,
                        severity=severity,
                        base_score=base_score,
                        vendor_names=vendors,
                        product_names=products,
                        references_json=refs,
                        source_url=source_url,
                        raw_payload_json=json.dumps(item, ensure_ascii=False),
                    )

            total_pages = payload.get("totalPages") or payload.get("pageCount")
            if total_pages is not None and page + 1 >= int(total_pages):
                break
            if len(items) < self.PAGE_SIZE:
                break
            page += 1

        self._log(f"[INFO] EUVD {year}: import finished pages={pages_seen} records={len(emitted)}")

    def _extract_items(self, payload) -> List[dict]:
        # Support several EUVD response layouts by locating the first list-like payload.
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("content", "items", "results", "vulnerabilities", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        return []

    def _extract_cve_ids_from_item(self, item: dict) -> List[str]:
        # EUVD records may store CVEs in multiple fields, so collect and deduplicate all candidates.
        direct = []
        for key in ("cveId", "cve", "id"):
            value = item.get(key)
            if isinstance(value, str) and value.upper().startswith("CVE-"):
                direct.append(value.upper())
        aliases = item.get("aliases") or item.get("alternateIds") or []
        if isinstance(aliases, list):
            for a in aliases:
                if isinstance(a, str) and a.upper().startswith("CVE-"):
                    direct.append(a.upper())
        if direct:
            return sorted(set(direct))
        return extract_cve_ids(json.dumps(item, ensure_ascii=False))

    def _extract_base_score(self, item: dict) -> Optional[float]:
        candidates = [
            self._pick_nested(item, ["cvss", "baseScore"]),
            self._pick_nested(item, ["cvssV3_1", "baseScore"]),
            self._pick_nested(item, ["cvssV3", "baseScore"]),
            self._pick_nested(item, ["score", "baseScore"]),
            self._pick_first(item, ["baseScore", "score"]),
        ]
        for value in candidates:
            try:
                if value is None or value == "":
                    continue
                num = float(value)
                if 0.0 <= num <= 10.0:
                    return num
            except (TypeError, ValueError):
                continue
        return None

    def _extract_severity(self, item: dict) -> Optional[str]:
        for value in [
            self._pick_nested(item, ["cvss", "baseSeverity"]),
            self._pick_nested(item, ["cvssV3_1", "baseSeverity"]),
            self._pick_nested(item, ["score", "baseSeverity"]),
            self._pick_first(item, ["severity", "baseSeverity", "riskLevel"]),
        ]:
            if isinstance(value, str) and value.strip():
                return value.strip()[:255]
        return None

    def _extract_named_values(self, item: dict, keys: List[str]) -> Set[str]:
        values: Set[str] = set()
        for key in keys:
            raw = item.get(key)
            if isinstance(raw, str) and raw.strip():
                values.add(raw.strip())
            elif isinstance(raw, list):
                for x in raw:
                    if isinstance(x, str) and x.strip():
                        values.add(x.strip())
                    elif isinstance(x, dict):
                        for inner_key in ("name", "value", "vendor", "product"):
                            v = x.get(inner_key)
                            if isinstance(v, str) and v.strip():
                                values.add(v.strip())
        return values

    def _extract_references(self, item: dict) -> List[str]:
        refs: List[str] = []
        for key in ("references", "links", "advisories"):
            raw = item.get(key)
            if isinstance(raw, list):
                for x in raw:
                    if isinstance(x, str) and valid_url(x):
                        refs.append(x)
                    elif isinstance(x, dict):
                        url = x.get("url") or x.get("href") or x.get("link")
                        if isinstance(url, str) and valid_url(url):
                            refs.append(url)
        return sorted(dict.fromkeys(refs))

    def _extract_source_id(self, item: dict, cve_ids: List[str]) -> str:
        for key in ("euvdId", "id", "uuid", "identifier"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return cve_ids[0]

    def _extract_source_url(self, item: dict, cve_ids: List[str], source_id: str) -> Optional[str]:
        for key in ("url", "link", "href"):
            value = item.get(key)
            if isinstance(value, str) and valid_url(value):
                return value
        for ref in self._extract_references(item):
            if "euvd.enisa.europa.eu" in ref:
                return ref
        if cve_ids:
            return f"https://euvd.enisa.europa.eu/vulnerability/{cve_ids[0]}"
        return f"https://euvd.enisa.europa.eu/vulnerability/{source_id}"

    @staticmethod
    def _pick_first(item: dict, keys: List[str]):
        for key in keys:
            value = item.get(key)
            if value not in (None, ""):
                return value
        return None

    @staticmethod
    def _pick_nested(item: dict, path: List[str]):
        cur = item
        for key in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur

    # @staticmethod
    # def _parse_euvd_date(value):
    #     if value in (None, "", "null"):
    #         return None
    #     if isinstance(value, datetime):
    #         return value.date()

    #     text = str(value).strip()
    #     if not text:
    #         return None

    #     parsed = parse_date(text)
    #     if parsed is not None:
    #         return parsed

    #     for fmt in (
    #         "%b %d, %Y, %I:%M:%S %p",
    #         "%B %d, %Y, %I:%M:%S %p",
    #         "%b %d, %Y, %I:%M %p",
    #         "%B %d, %Y, %I:%M %p",
    #     ):
    #         try:
    #             return datetime.strptime(text, fmt).date()
    #         except ValueError:
    #             continue
    #     return None

    from datetime import datetime

    @staticmethod
    def _parse_euvd_datetime(value):
        # Normalize EUVD date/time variants into Python datetime/date objects for metrics.
        if value in (None, "", "null"):
            return None
        if isinstance(value, datetime):
            return value

        text = str(value).strip()
        if not text:
            return None

        # Try ISO 8601 first.
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass

        # Fall back to date-only formats.
        for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue

        # Fall back to English datetime formats that may appear in EUVD responses.
        for fmt in (
            "%b %d, %Y, %I:%M:%S %p",
            "%B %d, %Y, %I:%M:%S %p",
            "%b %d, %Y, %I:%M %p",
            "%B %d, %Y, %I:%M %p",
        ):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue

        return None

    @staticmethod
    def _to_query(params: dict) -> str:
        parts = []
        for key, value in params.items():
            parts.append(f"{key}={value}")
        return "&".join(parts)
