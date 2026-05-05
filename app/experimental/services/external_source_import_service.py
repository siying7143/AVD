from typing import Dict, Iterable, List

from app.experimental.config import EXPERIMENTAL_TABLE_SOURCE_RECORDS
from app.experimental.sources.euvd_source_importer import EUVDSourceImporter
from app.experimental.sources.ghad_source_importer import GHADSourceImporter
from app.experimental.sources.jvn_source_importer import JVNSourceImporter
from app.experimental.sources.nvd_source_importer import NVDSourceImporter
from app.experimental.utils import to_json_text


class ExternalSourceImportService:
    def __init__(self, connection):
        self.connection = connection
        self.importers = {
            "NVD": NVDSourceImporter(),
            "JVN": JVNSourceImporter(),
            "EUVD": EUVDSourceImporter(),
            "GHAD": GHADSourceImporter(),
        }

    def import_sources(self, years: List[int], sources: List[str]) -> None:
        # Resolve importer classes from the registry and load each requested source/year pair.
        for source_name in sources:
            importer = self.importers[source_name]
            for year in years:
                print(f"[INFO] Importing external source {source_name} for {year}")
                rows = list(importer.import_year(year))
                self.upsert_rows(rows)
                self.connection.commit()
                print(f"[INFO] Imported {len(rows)} records for {source_name} {year}")

    def upsert_rows(self, rows: Iterable[Dict[str, object]]) -> None:
        # Upsert normalized source records so experiment reruns are repeatable and idempotent.
        rows = list(rows)
        if not rows:
            return

        sql = f"""
        INSERT INTO {EXPERIMENTAL_TABLE_SOURCE_RECORDS} (
            source_name,
            source_record_id,
            cve_id,
            cve_year,
            published_date,
            last_modified_date,
            severity,
            base_score,
            vendor_names,
            product_names,
            references_json,
            source_url,
            raw_payload_json
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON DUPLICATE KEY UPDATE
            published_date = VALUES(published_date),
            last_modified_date = VALUES(last_modified_date),
            severity = VALUES(severity),
            base_score = VALUES(base_score),
            vendor_names = VALUES(vendor_names),
            product_names = VALUES(product_names),
            references_json = VALUES(references_json),
            source_url = VALUES(source_url),
            raw_payload_json = VALUES(raw_payload_json)
        """

        payload = [
            (
                row["source_name"],
                row["source_record_id"],
                row["cve_id"],
                row["cve_year"],
                row["published_date"],
                row["last_modified_date"],
                row["severity"],
                float(row["base_score"]) if row["base_score"] is not None else None,
                to_json_text(row["vendor_names"]),
                to_json_text(row["product_names"]),
                to_json_text(row["references_json"]),
                row["source_url"],
                row["raw_payload_json"],
            )
            for row in rows
        ]

        with self.connection.cursor() as cursor:
            cursor.executemany(sql, payload)
