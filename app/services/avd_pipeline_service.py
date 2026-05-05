from typing import Iterable, List, Tuple

from app.config import DB_TABLE_VULNERABILITIES
from app.services.entry_service import EntryService
from app.services.assessment_service import AssessmentService


class AVDPipelineService:
    def __init__(self, connection):
        self.connection = connection
        self.entry_service = EntryService(connection)
        self.assessment_service = AssessmentService(connection)

    def get_vulnerability_rows(self, cve_ids: List[str]) -> List[Tuple[str, object, object]]:
        # Load only the CVEs that need downstream processing after import change detection.
        if not cve_ids:
            return []

        placeholders = ", ".join(["%s"] * len(cve_ids))
        sql = f"""
        SELECT cve_id, base_score, severity
        FROM {DB_TABLE_VULNERABILITIES}
        WHERE cve_id IN ({placeholders})
        """

        with self.connection.cursor() as cursor:
            cursor.execute(sql, cve_ids)
            return cursor.fetchall()

    def process_cve_ids(self, cve_ids: Iterable[str]) -> None:
        # Create or refresh the draft entry, calculate the assessment, then publish
        # the entry so the web portal can display it.
        cve_ids = list(dict.fromkeys(cve_ids))
        if not cve_ids:
            return

        rows = self.get_vulnerability_rows(cve_ids)

        for cve_id, base_score, base_severity in rows:
            # if base_score is None:
            #     continue

            self.entry_service.upsert_draft_entry(cve_id)
            assessment_id = self.assessment_service.create_assessment(
                cve_id,
                base_score,
                base_severity,
            )
            self.entry_service.publish_entry(cve_id, assessment_id)