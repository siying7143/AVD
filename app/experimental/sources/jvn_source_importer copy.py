import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse

from app.experimental.config import REQUEST_TIMEOUT, SOURCE_JVN
from app.experimental.sources.base import BaseSourceImporter
from app.experimental.utils import extract_cve_ids, extract_cve_year, parse_date


@dataclass
class AdvisoryAggregate:
    advisory_id: str
    source_url: Optional[str] = None
    published_date: Optional[object] = None
    last_modified_date: Optional[object] = None
    cve_ids: Set[str] = field(default_factory=set)
    vendor_names: Set[str] = field(default_factory=set)
    product_names: Set[str] = field(default_factory=set)
    references: Set[str] = field(default_factory=set)
    overview_payloads: Dict[str, dict] = field(default_factory=dict)
    detail_payloads: Dict[str, dict] = field(default_factory=dict)
    per_cve_score: Dict[str, float] = field(default_factory=dict)
    per_cve_severity: Dict[str, str] = field(default_factory=dict)
    advisory_level_score: Optional[float] = None
    advisory_level_severity: Optional[str] = None

    def merge_dates(self, published=None, modified=None) -> None:
        if published and (self.published_date is None or published < self.published_date):
            self.published_date = published
        if modified and (self.last_modified_date is None or modified > self.last_modified_date):
            self.last_modified_date = modified


class JVNSourceImporter(BaseSourceImporter):
    source_name = SOURCE_JVN

    FEED_URL_TEMPLATES = [
        "https://jvndb.jvn.jp/{lang}/feed/detail/jvndb_detail_{year}.rdf",
        "https://jvndb.jvn.jp/{lang}/rss/years/jvndb_{year}.rdf",
    ]
    MYJVN_ENDPOINT = "https://jvndb.jvn.jp/myjvn"
    LANGS = ("ja", "en")
    ALLOWED_DETAIL_HOSTS = {"jvndb.jvn.jp", "jvn.jp", "www.jvn.jp"}

    SCORE_RE = re.compile(r"\b(?:10(?:\.0+)?|[0-9](?:\.\d+)?)\b")
    SEVERITY_VALUES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
    JVNDB_ID_RE = re.compile(r"\bJVNDB-\d{4}-\d{6,}\b", re.IGNORECASE)

    def __init__(self):
        super().__init__()
        self._page_cache: Dict[str, str] = {}
        self._detail_cache: Dict[Tuple[str, str], Optional[dict]] = {}

    @staticmethod
    def _log(message: str) -> None:
        print(message, flush=True)

    def import_year(self, year: int) -> Iterable[dict]:
        advisories: Dict[str, AdvisoryAggregate] = {}
        self._log(f"[INFO] JVN {year}: import started")

        for lang in self.LANGS:
            for template in self.FEED_URL_TEMPLATES:
                url = template.format(lang=lang, year=year)
                try:
                    xml_text = self.get_bytes(url).decode("utf-8", errors="replace")
                except Exception as exc:
                    print(f"[WARN] JVN {year}: feed fetch failed: {url} ({exc})", flush=True)
                    continue
                added = self._ingest_feed_or_overview_xml(
                    advisories, xml_text, year, lang=lang, source_hint=url
                )
                self._log(
                    f"[INFO] JVN {year}: feed lang={lang} added={added} advisories_total={len(advisories)}"
                )

        for lang in self.LANGS:
            self._log(f"[INFO] JVN {year}: overview lang={lang} start advisories_total={len(advisories)}")
            self._fetch_overview_pages(advisories, year, lang=lang)
            self._log(f"[INFO] JVN {year}: overview lang={lang} done advisories_total={len(advisories)}")

        total_advisories = len(advisories)
        self._log(f"[INFO] JVN {year}: detail enrichment start advisories_total={total_advisories}")
        detail_hits = 0

        for idx, (advisory_id, agg) in enumerate(advisories.items(), start=1):
            for lang in self.LANGS:
                detail = self._fetch_detail(advisory_id, lang=lang)
                if detail:
                    self._merge_detail_payload(agg, detail, lang=lang)
                    detail_hits += 1

            if idx == 1 or idx % 100 == 0 or idx == total_advisories:
                scored = sum(
                    1
                    for a in advisories.values()
                    if a.per_cve_score or a.advisory_level_score is not None
                )
                with_products = sum(1 for a in advisories.values() if a.product_names)
                self._log(
                    f"[INFO] JVN {year}: detail progress "
                    f"{idx}/{total_advisories} detail_hits={detail_hits} "
                    f"scored_advisories={scored} product_advisories={with_products}"
                )

        emitted_records = 0
        scored_records = 0
        product_records = 0

        for advisory_id, agg in sorted(advisories.items()):
            cve_ids = sorted(c for c in agg.cve_ids if extract_cve_year(c) == year)
            if not cve_ids:
                continue

            for cve_id in cve_ids:
                refs = sorted(agg.references)
                source_url = agg.source_url or (refs[0] if refs else None)

                record_score = agg.per_cve_score.get(cve_id)
                record_severity = agg.per_cve_severity.get(cve_id)

                # For single-CVE advisories, use the advisory-level score as a fallback.
                if len(cve_ids) == 1:
                    if record_score is None:
                        record_score = agg.advisory_level_score
                    if not record_severity:
                        record_severity = agg.advisory_level_severity

                if record_score is not None or record_severity:
                    scored_records += 1

                if agg.product_names:
                    product_records += 1

                if record_score is None:
                    self._log(
                        f"[DEBUG] JVN {year} no score: "
                        f"advisory={advisory_id} cve={cve_id} "
                        f"known_cves={cve_ids} "
                        f"per_cve_score={agg.per_cve_score} "
                        f"advisory_level_score={agg.advisory_level_score}"
                    )

                emitted_records += 1
                yield self.normalize_record(
                    source_record_id=f"{advisory_id}::{cve_id}",
                    cve_id=cve_id,
                    cve_year=year,
                    published_date=agg.published_date,
                    last_modified_date=agg.last_modified_date,
                    severity=record_severity,
                    base_score=record_score,
                    vendor_names=sorted(agg.vendor_names),
                    product_names=sorted(agg.product_names),
                    references_json=refs,
                    source_url=source_url,
                    raw_payload_json=json.dumps(
                        {
                            "overview": agg.overview_payloads,
                            "detail": agg.detail_payloads,
                            "advisory_level_score": agg.advisory_level_score,
                            "advisory_level_severity": agg.advisory_level_severity,
                        },
                        ensure_ascii=False,
                    ),
                )

        self._log(
            f"[INFO] JVN {year}: import finished "
            f"advisories={len(advisories)} records={emitted_records} "
            f"scored_records={scored_records} product_records={product_records}"
        )

    def _fetch_overview_pages(self, advisories: Dict[str, AdvisoryAggregate], year: int, lang: str) -> None:
        start_item = 1
        page_size = 50
        max_pages = 400

        for page_no in range(1, max_pages + 1):
            params = {
                "method": "getVulnOverviewList",
                "feed": "hnd",
                "lang": lang,
                "startItem": start_item,
                "maxCountItem": page_size,
                "rangeDatePublished": "n",
                "rangeDatePublic": "n",
                "rangeDateFirstPublished": "n",
                "datePublishedStartY": year,
                "datePublishedStartM": 1,
                "datePublishedStartD": 1,
                "datePublishedEndY": year,
                "datePublishedEndM": 12,
                "datePublishedEndD": 31,
            }
            url = f"{self.MYJVN_ENDPOINT}?{urlencode(params)}"
            try:
                xml_text = self.get_bytes(url).decode("utf-8", errors="replace")
            except Exception as exc:
                print(f"[WARN] JVN {year}: overview fetch failed: {url} ({exc})", flush=True)
                break

            before = len(advisories)
            added = self._ingest_feed_or_overview_xml(
                advisories, xml_text, year, lang=lang, source_hint=url
            )
            if page_no == 1 or page_no % 5 == 0 or added == 0:
                self._log(
                    f"[INFO] JVN {year}: overview lang={lang} page={page_no} "
                    f"start_item={start_item} added={added} advisories_total={len(advisories)}"
                )
            if added == 0 and len(advisories) == before:
                break
            start_item += page_size

    def _fetch_detail(self, advisory_id: str, lang: str) -> Optional[dict]:
        cache_key = (advisory_id, lang)
        if cache_key in self._detail_cache:
            return self._detail_cache[cache_key]

        params = {
            "method": "getVulnDetailInfo",
            "feed": "hnd",
            "lang": lang,
            "maxCountItem": 10,
            "vulnId": advisory_id,
        }
        url = f"{self.MYJVN_ENDPOINT}?{urlencode(params)}"
        try:
            xml_text = self.get_bytes(url).decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"[WARN] JVN detail fetch failed: {advisory_id} {lang} ({exc})", flush=True)
            self._detail_cache[cache_key] = None
            return None

        parsed = self._parse_detail_xml(xml_text, advisory_id, lang=lang, source_hint=url)
        self._detail_cache[cache_key] = parsed
        return parsed

    def _ingest_feed_or_overview_xml(
        self,
        advisories: Dict[str, AdvisoryAggregate],
        xml_text: str,
        year: int,
        *,
        lang: str,
        source_hint: str,
    ) -> int:
        entries = self._parse_feed_or_overview_xml(xml_text, year, source_hint=source_hint)
        count = 0
        for entry in entries:
            advisory_id = entry["advisory_id"]
            agg = advisories.setdefault(advisory_id, AdvisoryAggregate(advisory_id=advisory_id))
            agg.cve_ids.update(entry["cve_ids"])
            agg.references.update(entry["references"])
            agg.vendor_names.update(entry["vendor_names"])
            agg.merge_dates(entry.get("published_date"), entry.get("last_modified_date"))
            if entry.get("source_url") and not agg.source_url:
                agg.source_url = entry["source_url"]
            agg.overview_payloads[f"{lang}:{source_hint}"] = entry["raw"]
            count += 1
        return count

    def _parse_feed_or_overview_xml(self, xml_text: str, year: int, source_hint: str) -> List[dict]:
        text_l = xml_text.lower()
        if "<html" in text_l and "<rdf" not in text_l and "<rss" not in text_l:
            return []

        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return []

        nodes = []
        for elem in root.iter():
            if self._local_name(elem.tag).lower() in {"item", "entry"}:
                nodes.append(elem)

        records = []
        seen = set()

        for node in nodes:
            title = self._child_text_or_attr(node, "title")
            identifier = self._child_text_or_attr(node, "identifier")
            link = self._extract_best_link(node)
            description = self._child_text_or_attr(node, "description")
            publisher = self._child_text_or_attr(node, "publisher")
            issued = (
                self._child_text_or_attr(node, "issued")
                or self._child_text_or_attr(node, "published")
                or self._child_text_or_attr(node, "date")
            )
            modified = (
                self._child_text_or_attr(node, "modified")
                or self._child_text_or_attr(node, "updated")
            )
            blob = self._collect_node_blob(node)

            advisory_id = identifier or self._extract_jvndb_id(
                "\n".join([title, description, link, blob])
            )
            if not advisory_id:
                continue

            cve_ids = extract_cve_ids("\n".join([title, description, identifier, link, blob]))
            if not cve_ids and link and self._is_allowed_detail_link(link):
                page_text = self._fetch_page_text(link)
                cve_ids = extract_cve_ids(page_text)

            cve_ids = [c for c in cve_ids if extract_cve_year(c) == year]
            if not cve_ids:
                continue

            refs = self._extract_reference_urls("\n".join([link, description, blob]))
            if link and link not in refs:
                refs.insert(0, link)

            key = (advisory_id, tuple(sorted(cve_ids)))
            if key in seen:
                continue
            seen.add(key)

            records.append(
                {
                    "advisory_id": advisory_id,
                    "cve_ids": cve_ids,
                    "published_date": self._smart_parse_date(issued),
                    "last_modified_date": self._smart_parse_date(modified),
                    "vendor_names": [publisher] if publisher else [],
                    "references": refs,
                    "source_url": link or source_hint,
                    "raw": {
                        "title": title,
                        "identifier": identifier,
                        "link": link,
                        "description": (description or "")[:2000],
                        "issued": issued,
                        "modified": modified,
                        "publisher": publisher,
                        "source_hint": source_hint,
                    },
                }
            )

        return records

    def _parse_detail_xml(self, xml_text: str, advisory_id: str, *, lang: str, source_hint: str) -> Optional[dict]:
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return None

        blob = self._collect_node_blob(root)
        cve_ids = extract_cve_ids(blob)
        refs = self._extract_reference_urls(blob)

        per_cve_score, per_cve_severity = self._extract_cvss_by_cve_structured(root)
        advisory_level_score, advisory_level_severity = self._extract_advisory_level_cvss(root, blob)

        source_url = None
        for url in refs:
            if self._is_allowed_detail_link(url):
                source_url = url
                break

        if not source_url:
            source_url = self._guess_detail_url(advisory_id, lang)
            if source_url:
                refs.insert(0, source_url)

        page_text = self._fetch_page_text(source_url) if source_url else ""
        if page_text:
            cve_ids = sorted(set(cve_ids) | set(extract_cve_ids(page_text)))

            fallback_score, fallback_severity = self._extract_cvss_by_cve_from_text(page_text)
            for key, value in fallback_score.items():
                per_cve_score.setdefault(key, value)
            for key, value in fallback_severity.items():
                per_cve_severity.setdefault(key, value)

            if advisory_level_score is None or not advisory_level_severity:
                page_score, page_severity = self._extract_advisory_level_cvss_from_text(page_text)
                if advisory_level_score is None:
                    advisory_level_score = page_score
                if not advisory_level_severity:
                    advisory_level_severity = page_severity

        vendors, products = self._extract_vendors_products(root, page_text)
        published, modified = self._extract_dates(root, page_text)

        return {
            "advisory_id": advisory_id,
            "lang": lang,
            "cve_ids": cve_ids,
            "source_url": source_url,
            "references": refs,
            "vendor_names": sorted(vendors),
            "product_names": sorted(products),
            "published_date": published,
            "last_modified_date": modified,
            "per_cve_score": per_cve_score,
            "per_cve_severity": per_cve_severity,
            "advisory_level_score": advisory_level_score,
            "advisory_level_severity": advisory_level_severity,
            "raw": {
                "source_hint": source_hint,
                "xml_excerpt": blob[:4000],
                "page_excerpt": page_text[:4000],
            },
        }

    def _merge_detail_payload(self, agg: AdvisoryAggregate, detail: dict, *, lang: str) -> None:
        agg.cve_ids.update(detail.get("cve_ids", []))
        agg.references.update(detail.get("references", []))
        agg.vendor_names.update(detail.get("vendor_names", []))
        agg.product_names.update(detail.get("product_names", []))
        agg.merge_dates(detail.get("published_date"), detail.get("last_modified_date"))

        if detail.get("source_url") and not agg.source_url:
            agg.source_url = detail["source_url"]

        agg.detail_payloads[lang] = detail.get("raw", {})

        for cve_id, score in detail.get("per_cve_score", {}).items():
            if cve_id not in agg.per_cve_score and score is not None:
                agg.per_cve_score[cve_id] = score

        for cve_id, severity in detail.get("per_cve_severity", {}).items():
            if cve_id not in agg.per_cve_severity and severity:
                agg.per_cve_severity[cve_id] = severity

        if agg.advisory_level_score is None and detail.get("advisory_level_score") is not None:
            agg.advisory_level_score = detail["advisory_level_score"]

        if not agg.advisory_level_severity and detail.get("advisory_level_severity"):
            agg.advisory_level_severity = detail["advisory_level_severity"]

    def _extract_cvss_by_cve_structured(self, root) -> Tuple[Dict[str, float], Dict[str, str]]:
        scores: Dict[str, float] = {}
        severities: Dict[str, str] = {}
        current_cve = None

        for elem in root.iter():
            name = self._local_name(elem.tag).lower()
            text = (elem.text or "").strip()
            if not text:
                continue

            maybe_cves = extract_cve_ids(text)
            if maybe_cves:
                current_cve = maybe_cves[0]
                continue

            if current_cve and name in {"base", "basescore", "score"}:
                try:
                    value = float(text)
                except ValueError:
                    value = None
                if value is not None and 0.0 <= value <= 10.0 and current_cve not in scores:
                    scores[current_cve] = value
                    continue

            if current_cve and name in {"severity", "baseseverity"}:
                sev = text.strip().upper()
                if sev in self.SEVERITY_VALUES and current_cve not in severities:
                    severities[current_cve] = sev

        return scores, severities

    def _extract_advisory_level_cvss(self, root, blob: str) -> Tuple[Optional[float], Optional[str]]:
        score = None
        severity = None

        # 1) Prefer structured XML tags.
        for elem in root.iter():
            name = self._local_name(elem.tag).lower()
            text = (elem.text or "").strip()
            if not text:
                continue

            if score is None and name in {"base", "basescore", "score"}:
                try:
                    value = float(text)
                except ValueError:
                    value = None
                if value is not None and 0.0 <= value <= 10.0:
                    score = value

            if not severity and name in {"severity", "baseseverity"}:
                sev = text.upper()
                if sev in self.SEVERITY_VALUES:
                    severity = sev

            if score is not None and severity:
                break

        # 2) Fall back to blob text parsing.
        if score is None:
            score, blob_severity = self._extract_advisory_level_cvss_from_text(blob)
            if not severity:
                severity = blob_severity
        elif not severity:
            _, blob_severity = self._extract_advisory_level_cvss_from_text(blob)
            severity = blob_severity

        return score, severity

    def _extract_cvss_by_cve_from_text(self, text: str) -> Tuple[Dict[str, float], Dict[str, str]]:
        scores: Dict[str, float] = {}
        severities: Dict[str, str] = {}
        normalized = re.sub(r"\s+", " ", text)

        for cve_id in extract_cve_ids(normalized):
            window_match = re.search(
                rf"({re.escape(cve_id)}.{{0,800}})",
                normalized,
                flags=re.IGNORECASE,
            )
            if not window_match:
                continue

            window = window_match.group(1)

            sev_match = re.search(
                r"\b(CRITICAL|HIGH|MEDIUM|LOW|NONE)\b",
                window,
                flags=re.IGNORECASE,
            )
            if sev_match:
                severities[cve_id] = sev_match.group(1).upper()

            # Prefer explicit CVSS or Base Score patterns.
            score_match = re.search(
                r"(?:CVSS[^0-9]{0,40}|Base\s+Score[^0-9]{0,20}|CVSSv?[23][^0-9]{0,20})"
                r"(10(?:\.0+)?|[0-9](?:\.\d+)?)",
                window,
                flags=re.IGNORECASE,
            )
            if not score_match:
                score_match = re.search(
                    r"\b(10(?:\.0+)?|[0-9](?:\.\d+)?)\b",
                    window,
                    flags=re.IGNORECASE,
                )

            if score_match:
                try:
                    score = float(score_match.group(1))
                except ValueError:
                    score = None
                if score is not None and 0.0 <= score <= 10.0:
                    scores[cve_id] = score

        return scores, severities

    def _extract_advisory_level_cvss_from_text(self, text: str) -> Tuple[Optional[float], Optional[str]]:
        if not text:
            return None, None

        normalized = re.sub(r"\s+", " ", text)

        sev_match = re.search(
            r"\b(CRITICAL|HIGH|MEDIUM|LOW|NONE)\b",
            normalized,
            flags=re.IGNORECASE,
        )
        severity = sev_match.group(1).upper() if sev_match else None

        patterns = [
            r"(?:CVSS[^0-9]{0,40}|Base\s+Score[^0-9]{0,20}|CVSSv?[23][^0-9]{0,20})(10(?:\.0+)?|[0-9](?:\.\d+)?)",
            r"(?:Score[^0-9]{0,20})(10(?:\.0+)?|[0-9](?:\.\d+)?)",
        ]

        for pattern in patterns:
            m = re.search(pattern, normalized, flags=re.IGNORECASE)
            if m:
                try:
                    value = float(m.group(1))
                except ValueError:
                    value = None
                if value is not None and 0.0 <= value <= 10.0:
                    return value, severity

        return None, severity

    def _extract_vendors_products(self, root, page_text: str) -> Tuple[Set[str], Set[str]]:
        vendors: Set[str] = set()
        products: Set[str] = set()

        for elem in root.iter():
            name = self._local_name(elem.tag).lower()
            text = (elem.text or "").strip()
            if not text:
                continue

            if name in {"vendor", "vendorname", "supplier"}:
                vendors.add(text)
            elif name in {"product", "productname", "prodname", "software"}:
                products.add(text)

        if page_text:
            for line in re.split(r"\s{2,}|\n|\r", page_text):
                s = line.strip(" -*:\t")
                if not s:
                    continue
                if re.search(r"\bAffected Products?\b", s, flags=re.IGNORECASE):
                    continue
                if len(products) < 50 and 2 <= len(s) <= 200 and "CVE-" not in s and "http" not in s:
                    if any(ch.isalpha() for ch in s) and any(ch in s for ch in [" ", "-", "/", "_"]):
                        products.add(s)

        return vendors, products

    def _extract_dates(self, root, page_text: str):
        published = None
        modified = None

        for elem in root.iter():
            text = (elem.text or "").strip()
            if not text:
                continue

            name = self._local_name(elem.tag).lower()
            if name in {"issued", "published", "datefirstpublished", "datepublic", "date"} and published is None:
                published = self._smart_parse_date(text)
            elif name in {"modified", "updated", "datelastupdated"} and modified is None:
                modified = self._smart_parse_date(text)

        if page_text:
            if published is None:
                m = re.search(
                    r"(?:Date\s+First\s+Published|Date\s+Public|Published)[:\s]+(\d{4}[/-]\d{2}[/-]\d{2})",
                    page_text,
                    flags=re.IGNORECASE,
                )
                if m:
                    published = self._smart_parse_date(m.group(1))

            if modified is None:
                m = re.search(
                    r"(?:Date\s+Last\s+Updated|Updated|Modified)[:\s]+(\d{4}[/-]\d{2}[/-]\d{2})",
                    page_text,
                    flags=re.IGNORECASE,
                )
                if m:
                    modified = self._smart_parse_date(m.group(1))

        return published, modified

    def _guess_detail_url(self, advisory_id: str, lang: str) -> Optional[str]:
        return f"https://jvndb.jvn.jp/{lang}/contents/{advisory_id[:4]}/{advisory_id}.html"

    def _fetch_page_text(self, url: Optional[str]) -> str:
        if not url:
            return ""

        if url in self._page_cache:
            return self._page_cache[url]

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except Exception:
            self._page_cache[url] = ""
            return ""

        html = response.text
        html = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        html = re.sub(r"<style.*?>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        self._page_cache[url] = text
        return text

    def _is_allowed_detail_link(self, url: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return host in self.ALLOWED_DETAIL_HOSTS

    @staticmethod
    def _local_name(tag: str) -> str:
        if "}" in tag:
            return tag.split("}", 1)[1]
        if ":" in tag:
            return tag.split(":", 1)[1]
        return tag

    def _child_text_or_attr(self, elem, local_name: str) -> str:
        for child in elem:
            if self._local_name(child.tag).lower() == local_name.lower():
                text = (child.text or "").strip()
                if text:
                    return text
                for value in child.attrib.values():
                    value = str(value).strip()
                    if value:
                        return value
        return ""

    def _extract_best_link(self, elem) -> str:
        urls = []

        direct_link = self._child_text_or_attr(elem, "link")
        if direct_link.startswith(("http://", "https://")):
            urls.append(direct_link)

        for node in elem.iter():
            for attr_value in node.attrib.values():
                attr_value = str(attr_value).strip()
                if attr_value.startswith(("http://", "https://")):
                    urls.append(attr_value)

        urls.extend(self._extract_reference_urls(self._collect_node_blob(elem)))
        urls = list(dict.fromkeys(urls))
        if not urls:
            return ""

        def score(url: str) -> int:
            lu = url.lower()
            value = 0
            if "jvndb.jvn.jp" in lu:
                value += 100
            elif "jvn.jp" in lu:
                value += 80
            if "/contents/" in lu:
                value += 30
            if "jvndb-" in lu:
                value += 20
            if "/myjvn" in lu:
                value += 5
            return value

        urls.sort(key=score, reverse=True)
        return urls[0]

    def _collect_node_blob(self, elem) -> str:
        parts = []
        for text in elem.itertext():
            text = text.strip()
            if text:
                parts.append(text)
        for node in elem.iter():
            for attr_value in node.attrib.values():
                attr_value = str(attr_value).strip()
                if attr_value:
                    parts.append(attr_value)
        return " ".join(parts)

    @staticmethod
    def _extract_reference_urls(text: str) -> List[str]:
        if not text:
            return []
        found = re.findall(r"https?://[^\s\"'<>]+", text)
        urls = []
        for value in found:
            value = value.rstrip(".,);]")
            if value:
                urls.append(value)
        return sorted(dict.fromkeys(urls))

    def _smart_parse_date(self, value) -> Optional[object]:
        if value in (None, "", "null"):
            return None
        return parse_date(str(value).replace("/", "-"))

    def _extract_jvndb_id(self, text: str) -> str:
        if not text:
            return ""
        m = self.JVNDB_ID_RE.search(text)
        return m.group(0).upper() if m else ""