from app.config import DEFAULT_YEARS
from app.db import get_connection
from app.importers.nvd_importer import NVDImporter


# Main entry point for the core NVD import pipeline.
def main():
    # Open one database connection for the full import run so inserts and
    # downstream enrichment steps can share the same transaction context.
    conn = get_connection()
    try:
        # Import vulnerability records for the configured default years.
        importer = NVDImporter(conn)
        # DEFAULT_YEARS is configured in app/config.py; the importer filters out
        # unchanged CVEs before triggering downstream AVD processing.
        importer.import_years(DEFAULT_YEARS)
        print("[INFO] All imports finished successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()