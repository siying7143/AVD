import concurrent.futures as cf
import html
import re
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from io import BytesIO
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.config import REQUEST_TIMEOUT
from app.services.source_registry import AU_SIGNAL_SOURCES


BASE_URL = "https://www.cyber.gov.au"


@dataclass
class AdvisoryResult:
    url: str
    title: str
    cves: list[str]
    source: str
    page_url: str


class AUSignalEnricher:
    CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,}\b", re.IGNORECASE)
    CRITICAL_ALERT_PATTERN = re.compile(r"\bcritical alert\b", re.IGNORECASE)

    def __init__(self):
        self._au_signal_cache: Optional[Dict[str, dict]] = None
        self._page_cache: Dict[str, str] = {}
        self._page_html_cache: Dict[str, str] = {}
        self._pdf_cache: Dict[str, str] = {}
        self._headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AVD-Enrichment/1.0"
            )
        }
        self._session = self._build_session()

    def get_signal_result(self, cve_id: str) -> dict:
        # Return the best available Australian relevance signal for a CVE, or a
        # neutral result when no ACSC/ASD evidence is found.
        normalized_cve = cve_id.strip().upper()
        au_signal_map = self.load_au_signal_map()

        if normalized_cve in au_signal_map:
            record = dict(au_signal_map[normalized_cve])
            record.pop("_priority", None)
            return record

        return {
            "au_signal_score": Decimal("0.0"),
            "au_signal_source": None,
            "au_signal_external_id": None,
            "au_signal_source_url": None,
            "au_signal_label": None,
        }

    def load_au_signal_map(self) -> Dict[str, dict]:
        # Combine RSS, listing pages, and PDF fallback sources into one CVE-indexed map.
        if self._au_signal_cache is not None:
            return self._au_signal_cache

        print("[INFO] AU signal: loading ACSC RSS, ACSC advisory history, and ASD reports...")

        result: Dict[str, dict] = {}

        # Stage 1: RSS
        for source_key, source_config in AU_SIGNAL_SOURCES.items():
            if not source_config.get("enabled", False):
                continue
            if source_config.get("source_type") != "rss":
                continue

            try:
                source_map = self.load_cves_from_rss(source_config)
                self.merge_signal_map(result, source_map)
            except Exception as exc:
                print(f"[WARN] AU signal: failed RSS source {source_key}: {exc}")

        # Stage 2: Historical alerts/advisories listing
        for source_key, source_config in AU_SIGNAL_SOURCES.items():
            if not source_config.get("enabled", False):
                continue
            if source_config.get("source_type") != "cyber_advisory_listing":
                continue

            try:
                source_map = self.load_cves_from_cyber_advisory_listing(source_config)
                self.merge_signal_map(result, source_map)
            except Exception as exc:
                print(f"[WARN] AU signal: failed historical advisory source {source_key}: {exc}")

        # Stage 3: PDF fallback
        for source_key, source_config in AU_SIGNAL_SOURCES.items():
            if not source_config.get("enabled", False):
                continue
            if source_config.get("source_type") != "pdf":
                continue

            try:
                source_map = self.load_cves_from_pdf(source_config)
                self.merge_signal_map(result, source_map)
            except Exception as exc:
                print(f"[WARN] AU signal: failed PDF source {source_key}: {exc}")

        self._au_signal_cache = result
        print(f"[INFO] AU signal: loaded {len(result)} CVE matches")
        return self._au_signal_cache

    def merge_signal_map(self, result: Dict[str, dict], source_map: Dict[str, dict]) -> None:
        # Merge source results while keeping the strongest/highest-confidence signal per CVE.
        for cve_id, signal_data in source_map.items():
            existing = result.get(cve_id)
            if self.should_replace(existing, signal_data):
                result[cve_id] = signal_data

    def should_replace(self, existing: Optional[dict], candidate: dict) -> bool:
        # Prefer confirmed Australian alerts over weaker keyword matches or fallback evidence.
        if existing is None:
            return True

        existing_score = Decimal(str(existing["au_signal_score"]))
        candidate_score = Decimal(str(candidate["au_signal_score"]))

        if candidate_score > existing_score:
            return True
        if candidate_score < existing_score:
            return False

        existing_priority = int(existing.get("_priority", 0))
        candidate_priority = int(candidate.get("_priority", 0))
        return candidate_priority > existing_priority

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "HEAD"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(self._headers)
        return session

    def get(self, url: str) -> requests.Response:
        response = self._session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response

    def load_cves_from_rss(self, source_config: dict) -> Dict[str, dict]:
        response = self.get(source_config["url"])
        root = ET.fromstring(response.text)
        result: Dict[str, dict] = {}

        for item in root.findall(".//item"):
            title = self.get_xml_text(item, "title")
            link = self.get_xml_text(item, "link")
            description = self.get_xml_text(item, "description")

            item_text = self.clean_html_text(f"{title}\n{description}")
            page_text = self.fetch_page_text(link) if link else ""

            full_text = f"{title}\n{item_text}\n{page_text}".strip()
            found_cves = self.extract_cves(full_text)
            if not found_cves:
                continue

            score, label = self.classify_signal(source_config, title, item_text, page_text)

            for cve_id in found_cves:
                result[cve_id] = {
                    "au_signal_score": score,
                    "au_signal_source": source_config["source_name"],
                    "au_signal_external_id": cve_id,
                    "au_signal_source_url": link or source_config["url"],
                    "au_signal_label": label,
                    "_priority": source_config.get("priority", 0),
                }

        return result

    def load_cves_from_cyber_advisory_listing(self, source_config: dict) -> Dict[str, dict]:
        listing_items = []

        for start_url in source_config["start_urls"]:
            source = "archive" if start_url.endswith("/archive") else "current"
            listing_items.extend(self.crawl_listing(start_url, source=source, delay=0.05))

        deduped: Dict[str, Tuple[str, str, list[str], str, str]] = {}
        for advisory_url, title_guess, snippet_cves, source, page_url in listing_items:
            if advisory_url not in deduped:
                deduped[advisory_url] = (advisory_url, title_guess, snippet_cves, source, page_url)
            else:
                old = deduped[advisory_url]
                deduped[advisory_url] = (
                    old[0],
                    old[1] or title_guess,
                    sorted(set(old[2]) | set(snippet_cves)),
                    old[3],
                    old[4],
                )

        results: list[AdvisoryResult] = []

        with cf.ThreadPoolExecutor(max_workers=10) as executor:
            future_map = {
                executor.submit(
                    self.fetch_advisory,
                    advisory_url,
                    title_guess,
                    source,
                    page_url,
                ): (advisory_url, snippet_cves)
                for advisory_url, title_guess, snippet_cves, source, page_url in deduped.values()
            }

            for future in cf.as_completed(future_map):
                advisory_url, snippet_cves = future_map[future]
                try:
                    advisory = future.result()
                    advisory.cves = sorted(set(advisory.cves) | set(snippet_cves))
                    if advisory.cves:
                        results.append(advisory)
                except Exception as exc:
                    print(f"[WARN] AU signal: failed advisory detail page {advisory_url}: {exc}")
                    if snippet_cves:
                        results.append(
                            AdvisoryResult(
                                url=advisory_url,
                                title=advisory_url,
                                cves=sorted(set(snippet_cves)),
                                source="unknown",
                                page_url="",
                            )
                        )

        result: Dict[str, dict] = {}
        for advisory in results:
            score, label = self.classify_signal(
                source_config,
                advisory.title,
                advisory.title,
                "",
            )

            for cve_id in advisory.cves:
                candidate = {
                    "au_signal_score": score,
                    "au_signal_source": source_config["source_name"],
                    "au_signal_external_id": cve_id,
                    "au_signal_source_url": advisory.url,
                    "au_signal_label": label,
                    "_priority": source_config.get("priority", 0),
                }

                existing = result.get(cve_id)
                if self.should_replace(existing, candidate):
                    result[cve_id] = candidate

        return result

    def crawl_listing(self, start_url: str, source: str, delay: float) -> list[Tuple[str, str, list[str], str, str]]:
        # Follow paginated advisory listings and extract CVEs from each advisory page.
        page_url = start_url
        visited_pages = set()
        advisories: Dict[str, Tuple[str, str, list[str], str, str]] = {}

        while page_url and page_url not in visited_pages:
            visited_pages.add(page_url)
            soup = BeautifulSoup(self.get(page_url).text, "html.parser")

            for advisory_url, title_guess, snippet_cves in self.extract_listing_cards(soup, page_url):
                if advisory_url not in advisories:
                    advisories[advisory_url] = (advisory_url, title_guess, snippet_cves, source, page_url)
                else:
                    old = advisories[advisory_url]
                    merged = sorted(set(old[2]) | set(snippet_cves))
                    advisories[advisory_url] = (old[0], old[1], merged, old[3], old[4])

            next_url = self.find_next_page(soup, page_url)
            if next_url and next_url in visited_pages:
                break
            page_url = next_url
            if page_url and delay > 0:
                time.sleep(delay)

        return list(advisories.values())

    def fetch_advisory(self, advisory_url: str, title_guess: str, source: str, page_url: str) -> AdvisoryResult:
        soup = BeautifulSoup(self.get(advisory_url).text, "html.parser")
        page_text = self.clean_text(soup)

        title = title_guess
        h1 = soup.find("h1")
        if h1:
            title = " ".join(h1.stripped_strings)
        elif soup.title and soup.title.string:
            title = soup.title.string.strip()

        cves = self.normalize_cves(page_text)
        return AdvisoryResult(
            url=advisory_url,
            title=title,
            cves=cves,
            source=source,
            page_url=page_url,
        )

    def extract_listing_cards(self, soup: BeautifulSoup, page_url: str) -> list[Tuple[str, str, list[str]]]:
        results: list[Tuple[str, str, list[str]]] = []
        seen = set()

        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(page_url, href)

            if "/about-us/view-all-content/alerts-and-advisories" not in full_url:
                continue
            if full_url.rstrip("/") == page_url.rstrip("/"):
                continue

            text = " ".join(a.stripped_strings)
            if not text:
                continue
            if len(text) < 40:
                continue

            key = full_url.split("#", 1)[0]
            if key in seen:
                continue

            seen.add(key)
            title_guess = text.split("Audience focus:", 1)[0].strip()
            results.append((key, title_guess, self.normalize_cves(text)))

        return results

    def find_next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
        rel_next = soup.select_one('link[rel="next"]')
        if rel_next and rel_next.get("href"):
            return urljoin(current_url, rel_next["href"])

        for a in soup.find_all("a", href=True):
            text = " ".join(a.stripped_strings).lower()
            aria = (a.get("aria-label") or "").lower()
            title = (a.get("title") or "").lower()

            if (
                "next page" in text
                or text in {"next", "next ››", "››"}
                or "next page" in aria
                or "next page" in title
            ):
                return urljoin(current_url, a["href"])

        return None

    def load_cves_from_pdf(self, source_config: dict) -> Dict[str, dict]:
        pdf_text = self.fetch_pdf_text(source_config["url"])
        found_cves = self.extract_cves(pdf_text)

        result: Dict[str, dict] = {}
        if not found_cves:
            return result

        score = Decimal(str(source_config["default_score"]))
        label = source_config["default_label"]

        for cve_id in found_cves:
            result[cve_id] = {
                "au_signal_score": score,
                "au_signal_source": source_config["source_name"],
                "au_signal_external_id": cve_id,
                "au_signal_source_url": source_config["url"],
                "au_signal_label": label,
                "_priority": source_config.get("priority", 0),
            }

        return result

    def classify_signal(self, source_config: dict, title: str, item_text: str, page_text: str):
        # Assign confidence labels based on the source type and whether the page
        # content contains explicit Australian cyber-advisory wording.
        combined = f"{title}\n{item_text}\n{page_text}"

        if self.CRITICAL_ALERT_PATTERN.search(combined):
            return Decimal("2.0"), "ACSC critical alert"

        default_score = Decimal(str(source_config["default_score"]))
        default_label = source_config["default_label"]
        return default_score, default_label

    def fetch_page_html(self, url: str) -> str:
        if not url:
            return ""

        if url in self._page_html_cache:
            return self._page_html_cache[url]

        html_text = self.get(url).text
        self._page_html_cache[url] = html_text
        return html_text

    def fetch_page_text(self, url: str) -> str:
        if not url:
            return ""

        if url in self._page_cache:
            return self._page_cache[url]

        html_text = self.fetch_page_html(url)
        text = self.clean_html_text(html_text)
        self._page_cache[url] = text
        return text

    def fetch_pdf_text(self, url: str) -> str:
        if url in self._pdf_cache:
            return self._pdf_cache[url]

        response = self.get(url)
        reader = PdfReader(BytesIO(response.content))
        pages = []

        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                pages.append("")

        text = "\n".join(pages)
        text = re.sub(r"\s+", " ", text).strip()

        self._pdf_cache[url] = text
        return text

    def normalize_cves(self, text: str) -> list[str]:
        cves = {m.group(0).upper() for m in self.CVE_PATTERN.finditer(text or "")}
        return sorted(cves)

    def extract_cves(self, text: str) -> Set[str]:
        return set(self.normalize_cves(text))

    @staticmethod
    def clean_text(soup: BeautifulSoup) -> str:
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup.get_text(" ", strip=True)

    @staticmethod
    def get_xml_text(parent, tag_name: str) -> str:
        element = parent.find(tag_name)
        if element is None or element.text is None:
            return ""
        return element.text.strip()

    @staticmethod
    def clean_html_text(raw_text: str) -> str:
        if not raw_text:
            return ""

        text = html.unescape(raw_text)
        text = re.sub(r"<script.*?>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<style.*?>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()