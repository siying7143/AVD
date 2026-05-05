import argparse
from collections import defaultdict
from pathlib import Path

from app.db import get_connection
from app.experimental.config import EXPERIMENTAL_SCENARIO_YEARS, SUPPORTED_EXTERNAL_SOURCES
from app.experimental.services.experimental_metrics_service import ExperimentalMetricsService
from app.experimental.services.external_source_import_service import ExternalSourceImportService
from app.experimental.services.schema_service import SchemaService


def parse_args():
    # CLI options let experiments be rerun for selected years/sources without
    # editing configuration files.
    parser = argparse.ArgumentParser(description="Run experimental metrics and cross-database comparisons.")
    parser.add_argument(
        "--years",
        nargs="+",
        type=int,
        default=EXPERIMENTAL_SCENARIO_YEARS,
        help="Scenario CVE years to process. Default: 2023 2024 2025",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=SUPPORTED_EXTERNAL_SOURCES,
        choices=SUPPORTED_EXTERNAL_SOURCES,
        help="External sources to import before metric calculation.",
    )
    parser.add_argument(
        "--skip-import",
        action="store_true",
        help="Skip external-source import and only recompute metrics from existing MySQL data.",
    )
    return parser.parse_args()


def _draw_table(headers, rows):
    # Render simple fixed-width tables so metric output stays readable in terminals.
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(sep)
    print("| " + " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)) + " |")
    print(sep)
    for row in rows:
        print("| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) + " |")
    print(sep)


def _format_duration_human(value: float, unit: str) -> str:
    # Convert raw seconds/days into compact labels such as 2d 4h 10m.
    if unit == "seconds":
        seconds = float(value)
    elif unit == "days":
        seconds = float(value) * 86400.0
    else:
        return f"{float(value):.2f}"

    sign = "-" if seconds < 0 else ""
    total = int(round(abs(seconds)))

    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")

    return sign + " ".join(parts)


def _format_metric(metric):
    if metric is None:
        return "-"

    value = float(metric.metric_value)
    unit = metric.unit or ""

    if metric.metric_name == "tte_mean":
        return _format_duration_human(value, unit)

    if unit == "percent":
        return f"{value:.2f}%"
    if unit == "score":
        return f"{value:+.4f}"

    return f"{value:.4f}"


def print_markdown_table(metrics):
    # Group metrics by scenario year and source before printing the comparison table.
    by_year = defaultdict(list)
    for m in metrics:
        by_year[m.scenario_year].append(m)

    metric_order = [
        "tte_mean",
        "coverage_vs_nvd",
        "completeness_score",
        "accuracy_structural_score",
        "prioritisation_avg_delta_vs_nvd",
    ]

    for year in sorted(by_year):
        items = by_year[year]

        idx = {}
        for m in items:
            idx[(m.subject_source, m.metric_name)] = m

        dbs = sorted({m.subject_source for m in items if m.subject_source != "NVD"})
        if "AVD" in dbs:
            dbs.remove("AVD")
            dbs = ["AVD"] + dbs

        rows = []
        for db in dbs:
            row = [db]
            for metric_name in metric_order:
                row.append(_format_metric(idx.get((db, metric_name))))
            rows.append(row)

        print()
        print(f"=== {year} ===")
        _draw_table(
            ["Database", "TTE", "Coverage(vs NVD)", "Completeness", "Accuracy", "Prioritisation(ΔvsNVD-AU)"],
            rows,
        )


def main():
    args = parse_args()
    # Always ensure the experimental schema exists before importing or recalculating metrics.
    conn = get_connection()
    try:
        schema_service = SchemaService(conn)
        schema_service.ensure_schema(Path(__file__).with_name("db_schema.sql"))

        # --skip-import is useful when source data already exists and only metrics
        # need to be recalculated after changing scoring logic.
        if not args.skip_import:
            import_service = ExternalSourceImportService(conn)
            import_service.import_sources(args.years, args.sources)

        metrics_service = ExperimentalMetricsService(conn)
        metrics = metrics_service.run(args.years)
        print_markdown_table(metrics)
        print("[INFO] Experimental metrics completed successfully.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()