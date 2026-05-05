import csv
import gzip
import io
import json
import zipfile
from abc import ABC, abstractmethod
from typing import Dict, Iterable, Iterator

import requests

from app.experimental.config import REQUEST_TIMEOUT


class BaseSourceImporter(ABC):
    # Shared HTTP and archive helpers keep individual source importers focused on
    # source-specific parsing and normalization rules.
    source_name: str = ""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AVD-ExperimentalMetrics/1.0"})

    def get_bytes(self, url: str) -> bytes:
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.content

    def get_json(self, url: str):
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def iter_json_lines(self, url: str) -> Iterator[dict]:
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)

    def read_gzip_json(self, url: str):
        payload = self.get_bytes(url)
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as gz:
            return json.load(gz)

    def iter_csv_rows(self, url: str) -> Iterator[dict]:
        response = self.session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        reader = csv.DictReader(io.StringIO(response.text))
        yield from reader

    def iter_zip_members(self, url: str, suffixes: tuple[str, ...]) -> Iterator[tuple[str, bytes]]:
        payload = self.get_bytes(url)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if not info.filename.lower().endswith(suffixes):
                    continue
                yield info.filename, archive.read(info)

    def normalize_record(
        self,
        *,
        source_record_id: str,
        cve_id: str,
        cve_year: int,
        published_date=None,
        last_modified_date=None,
        severity=None,
        base_score=None,
        vendor_names=None,
        product_names=None,
        references_json=None,
        source_url=None,
        raw_payload_json=None,
    ) -> Dict[str, object]:
        # Convert source-specific fields into the common experimental_source_records shape.
        return {
            "source_name": self.source_name,
            "source_record_id": source_record_id,
            "cve_id": cve_id,
            "cve_year": cve_year,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "severity": severity,
            "base_score": base_score,
            "vendor_names": vendor_names or [],
            "product_names": product_names or [],
            "references_json": references_json or [],
            "source_url": source_url,
            "raw_payload_json": raw_payload_json,
        }

    @abstractmethod
    def import_year(self, year: int) -> Iterable[Dict[str, object]]:
        # Each concrete importer yields normalized records for one scenario year.
        raise NotImplementedError
