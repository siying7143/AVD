from app.config import DB_TABLE_AVD_ENTRIES, SOURCE_NAME


class EntryService:
    def __init__(self, connection):
        self.connection = connection

    def upsert_draft_entry(self, cve_id: str) -> None:
        # Keep one draft row per CVE; reruns refresh timestamps instead of creating duplicates.
        sql = f"""
        INSERT INTO {DB_TABLE_AVD_ENTRIES} (
            cve_id,
            source_name,
            record_status,
            assessment_id,
            created_at,
            updated_at,
            published_at
        ) VALUES (%s, %s, 'draft', NULL, NOW(), NOW(), NULL)
        ON DUPLICATE KEY UPDATE
            source_name = VALUES(source_name),
            record_status = 'draft',
            updated_at = NOW()
        """

        with self.connection.cursor() as cursor:
            cursor.execute(sql, (cve_id, SOURCE_NAME))

    def publish_entry(self, cve_id: str, assessment_id: str) -> None:
        # Attach the latest assessment and mark the record as published for the read-only UI.
        sql = f"""
        UPDATE {DB_TABLE_AVD_ENTRIES}
        SET
            assessment_id = %s,
            record_status = 'published',
            published_at = CASE
                WHEN published_at IS NULL THEN NOW()
                ELSE published_at
            END,
            updated_at = NOW()
        WHERE cve_id = %s
        """

        with self.connection.cursor() as cursor:
            cursor.execute(sql, (assessment_id, cve_id))