import re
from dataclasses import dataclass
from datetime import date, datetime, time
from typing import Any, Dict, List, Optional, Tuple

from app.config import (
    DB_TABLE_AVD_ASSESSMENTS,
    DB_TABLE_AVD_ENTRIES,
    DB_TABLE_VULNERABILITIES,
)
from app.experimental.config import (
    EXPERIMENTAL_TABLE_METRICS,
    EXPERIMENTAL_TABLE_SOURCE_RECORDS,
    SOURCE_AVD,
    SOURCE_NVD,
    SUPPORTED_EXTERNAL_SOURCES,
)
from app.experimental.utils import from_json_text, percentage, safe_divide, valid_url


@dataclass
class MetricRow:
    scenario_year: int
    subject_source: str
    comparison_source: Optional[str]
    metric_name: str
    metric_value: float
    numerator_value: Optional[float] = None
    denominator_value: Optional[float] = None
    unit: str = "ratio"
    note: Optional[str] = None


class ExperimentalMetricsService:
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    # Accuracy weights are used only for non-empty field accuracy checks.
    COMMON_ACCURACY_WEIGHTS = {
        "score": 0.35,
        "severity": 0.20,
        "published_date": 0.15,
        "last_modified_date": 0.10,
        "vendors": 0.10,
        "products": 0.10,
    }

    AVD_INTERNAL_WEIGHTS = {
        "final_score_formula": 0.35,
        "priority_level": 0.20,
        "au_signal_source_url": 0.10,
        "exploit_source_url": 0.10,
        "au_signal_external_id": 0.10,
        "exploit_external_id": 0.10,
        "base_score_range": 0.05,
        "publication_latency": 0.10,
    }

    EXTERNAL_STRUCTURAL_WEIGHTS = {
        "source_url": 0.10,
        "references": 0.10,
    }

    def __init__(self, connection):
        self.connection = connection

    def run(self, scenario_years: List[int]) -> List[MetricRow]:
        # Calculate metrics for every scenario year, persist them, and return the
        # rows for console reporting.
        metrics: List[MetricRow] = []
        for year in scenario_years:
            print(f"[INFO] Calculating experimental metrics for scenario {year}")
            metrics.extend(self._calculate_year_metrics(year))

        self._replace_metrics(metrics, scenario_years)
        self.connection.commit()
        return metrics

    def _calculate_year_metrics(self, year: int) -> List[MetricRow]:
        # Build a common NVD baseline first, then compare AVD and external sources
        # against the same reference set.
        nvd_map = self._fetch_nvd_map(year)
        nvd_cves = set(nvd_map.keys())

        avd_map = self._fetch_avd_map(year, nvd_map)

        au_cves = {
            cve_id
            for cve_id, row in avd_map.items()
            if float(row.get("au_signal_score") or 0) != 0
        }

        sources = [SOURCE_AVD] + [s for s in SUPPORTED_EXTERNAL_SOURCES if s != SOURCE_NVD]
        external_maps = {
            s: self._fetch_external_map(s, year, nvd_map)
            for s in sources
            if s != SOURCE_AVD
        }

        metrics: List[MetricRow] = []
        for source in sources:
            source_map = avd_map if source == SOURCE_AVD else external_maps.get(source, {})
            metrics.extend(self._build_source_metrics(year, source, source_map, nvd_map, nvd_cves, au_cves))

        return metrics

    def _build_source_metrics(
        self,
        year: int,
        source: str,
        source_map: Dict[str, dict],
        nvd_map: Dict[str, dict],
        nvd_cves: set,
        au_cves: set,
    ) -> List[MetricRow]:
        # Compute the standard metric bundle for one source/year combination:
        # timeliness, coverage, completeness, accuracy, and prioritisation delta.
        rows = list(source_map.values())
        source_cves = set(source_map.keys())

        # TTE
        tte_values = []
        tte_unit = "seconds" if source == SOURCE_AVD else "days"

        zero_count = 0
        pos_count = 0
        neg_count = 0
        missing_count = 0

        for row in rows:
            if source == SOURCE_AVD:
                ingest = self._to_datetime(row.get("ingest_time"))
                published = self._to_datetime(row.get("publish_time"))
                if ingest is not None and published is not None and published >= ingest:
                    tte_values.append((published - ingest).total_seconds())
            else:
                source_pub = self._to_datetime(row.get("source_publish_time"))
                nvd_pub = self._to_datetime(row.get("nvd_publish_time"))

                if not source_pub or not nvd_pub:
                    missing_count += 1
                    continue

                delta_sec = (source_pub - nvd_pub).total_seconds()

                # If an external database published earlier than NVD, the signed gap is negative.
                # That is not an elapsed-time-to-entry value, so exclude it from TTE instead of
                # converting it with abs(). The counter is kept for audit/debug output.
                if delta_sec < 0:
                    neg_count += 1
                    continue
                if delta_sec == 0:
                    zero_count += 1
                else:
                    pos_count += 1

                delta_days = delta_sec / 86400.0
                tte_values.append(delta_days)

        if source != SOURCE_AVD:
            print(
                f"[DEBUG] TTE {source} {year}: rows={len(rows)} used={len(tte_values)} "
                f"zero={zero_count} positive={pos_count} negative={neg_count} missing={missing_count}",
                flush=True,
            )

        completeness_values = []
        for row in rows:
            if source == SOURCE_AVD:
                completeness_values.append(self._calculate_avd_completeness(row))
            else:
                completeness_values.append(self._calculate_external_completeness(row, source))

        coverage_n = len(source_cves & nvd_cves)
        coverage_d = len(nvd_cves)

        accuracy_score, accuracy_weight = self._calculate_accuracy(source, rows, nvd_map)

        deltas = []
        missing_in_source = []
        missing_in_nvd = []
        missing_src_score = []
        missing_nvd_score = []
        used_samples = []

        for cve_id in sorted(au_cves):
            src = source_map.get(cve_id)
            nvd = nvd_map.get(cve_id)

            if not src:
                missing_in_source.append(cve_id)
                continue
            if not nvd:
                missing_in_nvd.append(cve_id)
                continue

            src_score = src.get("score")
            nvd_score = nvd.get("base_score")

            if src_score is None:
                missing_src_score.append(cve_id)
                continue
            if nvd_score is None:
                missing_nvd_score.append(cve_id)
                continue

            delta = float(src_score) - float(nvd_score)
            deltas.append(delta)
            used_samples.append((cve_id, src_score, nvd_score, delta))

        print(
            f"[DEBUG] Prioritisation {source} {year}: "
            f"au_total={len(au_cves)}, "
            f"in_source={len(au_cves) - len(missing_in_source)}, "
            f"used={len(used_samples)}, "
            f"missing_in_source={len(missing_in_source)}, "
            f"missing_in_nvd={len(missing_in_nvd)}, "
            f"missing_src_score={len(missing_src_score)}, "
            f"missing_nvd_score={len(missing_nvd_score)}",
            flush=True,
        )

        if missing_in_source:
            print(
                f"[DEBUG] Prioritisation {source} {year} missing_in_source sample: "
                f"{missing_in_source[:10]}",
                flush=True,
            )

        if missing_src_score:
            print(
                f"[DEBUG] Prioritisation {source} {year} missing_src_score sample: "
                f"{missing_src_score[:10]}",
                flush=True,
            )

        if used_samples:
            print(
                f"[DEBUG] Prioritisation {source} {year} used_samples sample: "
                f"{used_samples[:10]}",
                flush=True,
            )
        else:
            print(
                f"[DEBUG] Prioritisation {source} {year}: no usable samples for delta",
                flush=True,
            )

        return [
            MetricRow(
                scenario_year=year,
                subject_source=source,
                comparison_source=SOURCE_NVD,
                metric_name="tte_mean",
                metric_value=self._avg(tte_values),
                numerator_value=sum(tte_values) if tte_values else 0.0,
                denominator_value=len(tte_values),
                unit=tte_unit,
                note="AVD: published_at-created_at from database; external: source_published-nvd_published; negative external gaps are excluded",
            ),
            MetricRow(
                scenario_year=year,
                subject_source=source,
                comparison_source=SOURCE_NVD,
                metric_name="completeness_score",
                metric_value=self._avg(completeness_values) * 100.0,
                numerator_value=sum(completeness_values),
                denominator_value=len(completeness_values),
                unit="percent",
                note="source-specific completeness",
            ),
            MetricRow(
                scenario_year=year,
                subject_source=source,
                comparison_source=SOURCE_NVD,
                metric_name="coverage_vs_nvd",
                metric_value=percentage(coverage_n, coverage_d),
                numerator_value=coverage_n,
                denominator_value=coverage_d,
                unit="percent",
                note="NVD baseline coverage",
            ),
            MetricRow(
                scenario_year=year,
                subject_source=source,
                comparison_source=SOURCE_NVD,
                metric_name="accuracy_structural_score",
                metric_value=(safe_divide(accuracy_score, accuracy_weight) * 100.0) if accuracy_weight else 0.0,
                numerator_value=accuracy_score,
                denominator_value=accuracy_weight,
                unit="percent",
                note="non-null field accuracy against NVD baseline + source-specific consistency checks",
            ),
            MetricRow(
                scenario_year=year,
                subject_source=source,
                comparison_source=SOURCE_NVD,
                metric_name="prioritisation_avg_delta_vs_nvd",
                metric_value=self._avg(deltas),
                numerator_value=sum(deltas) if deltas else 0.0,
                denominator_value=len(deltas),
                unit="score",
                note="AU CVEs only: source_score - NVD base_score",
            ),
        ]

    def _fetch_nvd_map(self, year: int) -> Dict[str, dict]:
        # Fetch baseline NVD records keyed by CVE ID for the selected scenario year.
        sql = f"""
        SELECT
            cve_id,
            base_score,
            severity,
            published_date,
            last_modified_date,
            vendors,
            product_names
        FROM {DB_TABLE_VULNERABILITIES}
        WHERE cve_id LIKE %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (f"CVE-{year}-%",))
            result = {}
            for row in cursor.fetchall():
                cve_id = row[0]
                result[cve_id] = {
                    "base_score": float(row[1]) if row[1] is not None else None,
                    "severity": row[2],
                    "published_date": self._to_datetime(row[3]),
                    "last_modified_date": self._to_datetime(row[4]),
                    "vendors": from_json_text(row[5], []),
                    "product_names": from_json_text(row[6], []),
                }
            return result

    def _fetch_avd_map(self, year: int, nvd_map: Dict[str, dict]) -> Dict[str, dict]:
        # Fetch published AVD records that correspond to the same CVE IDs in the
        # NVD baseline, preserving fair coverage comparisons.
        sql = f"""
        SELECT
            e.cve_id,
            e.created_at,
            e.published_at,
            e.record_status,
            e.assessment_id,
            a.base_score,
            a.base_severity,
            a.exploitation_risk_score,
            a.exploitation_risk_source,
            a.exploitation_risk_external_id,
            a.exploitation_risk_source_url,
            a.kev_status,
            a.epss_score,
            a.epss_percentile,
            a.au_signal_score,
            a.au_signal_source,
            a.au_signal_external_id,
            a.au_signal_source_url,
            a.au_signal_label,
            a.final_score,
            a.priority_level,
            a.assessed_at,
            v.vendors,
            v.product_names
        FROM {DB_TABLE_AVD_ENTRIES} e
        JOIN {DB_TABLE_AVD_ASSESSMENTS} a ON a.assessment_id = e.assessment_id
        LEFT JOIN {DB_TABLE_VULNERABILITIES} v ON v.cve_id = e.cve_id
        WHERE e.cve_id LIKE %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (f"CVE-{year}-%",))
            columns = [col[0] for col in cursor.description]
            raw_rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

        by_cve: Dict[str, dict] = {}
        for row in raw_rows:
            cve_id = row["cve_id"]
            current = by_cve.get(cve_id)

            assessed = self._to_datetime(row.get("assessed_at"))
            current_assessed = self._to_datetime(current.get("assessed_at")) if current else None
            if current and current_assessed and assessed and current_assessed >= assessed:
                continue

            final_score = row.get("final_score")
            base_score = row.get("base_score")
            score = float(final_score) if final_score is not None else (
                float(base_score) if base_score is not None else None
            )

            nvd_ref = nvd_map.get(cve_id, {})

            by_cve[cve_id] = {
                **row,
                "score": score,
                "ingest_time": self._to_datetime(row.get("created_at")),
                "publish_time": self._to_datetime(row.get("published_at")),
                "vendors": from_json_text(row.get("vendors"), []),
                "product_names": from_json_text(row.get("product_names"), []),
                "nvd_published_date": nvd_ref.get("published_date"),
                "nvd_last_modified_date": nvd_ref.get("last_modified_date"),
            }

        return by_cve

    def _fetch_external_map(self, source_name: str, year: int, nvd_map: Dict[str, dict]) -> Dict[str, dict]:
        # Fetch normalized records for one external source and align them by CVE ID.
        sql = f"""
        SELECT
            source_record_id,
            cve_id,
            published_date,
            inserted_at,
            severity,
            base_score,
            vendor_names,
            product_names,
            references_json,
            source_url,
            last_modified_date
        FROM {EXPERIMENTAL_TABLE_SOURCE_RECORDS}
        WHERE source_name = %s AND cve_year = %s
        """
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (source_name, year))
            columns = [col[0] for col in cursor.description]
            raw_rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

        grouped: Dict[str, list] = {}
        for row in raw_rows:
            grouped.setdefault(row["cve_id"], []).append(row)

        result: Dict[str, dict] = {}
        for cve_id, rows in grouped.items():
            rows_sorted = sorted(
                rows,
                key=lambda r: self._to_datetime(r.get("inserted_at")) or datetime.max
            )

            ingest_time = self._to_datetime(rows_sorted[0].get("inserted_at")) if rows_sorted else None

            source_pub_times = [
                self._to_datetime(r.get("published_date"))
                for r in rows_sorted
                if self._to_datetime(r.get("published_date")) is not None
            ]
            source_published_date = min(source_pub_times) if source_pub_times else None 
            nvd_ref = nvd_map.get(cve_id, {})
            nvd_published_date = nvd_ref.get("published_date")
            nvd_last_modified_date = nvd_ref.get("last_modified_date")

            score = None
            for r in rows_sorted:
                if r.get("base_score") is not None:
                    score = float(r["base_score"])
                    break

            severity = next((str(r["severity"]) for r in rows_sorted if r.get("severity")), None)
            source_url = next((r["source_url"] for r in rows_sorted if r.get("source_url")), None)

            source_modified_times = [
                self._to_datetime(r.get("last_modified_date"))
                for r in rows_sorted
                if self._to_datetime(r.get("last_modified_date")) is not None
            ]
            source_last_modified_date = max(source_modified_times) if source_modified_times else None

            refs = []
            vendors = []
            products = []
            for r in rows_sorted:
                refs.extend(from_json_text(r.get("references_json"), []))
                vendors.extend(from_json_text(r.get("vendor_names"), []))
                products.extend(from_json_text(r.get("product_names"), []))

            refs = sorted(dict.fromkeys(str(x) for x in refs if x))
            vendors = sorted(dict.fromkeys(str(x) for x in vendors if x))
            products = sorted(dict.fromkeys(str(x) for x in products if x))

            effective_publish_date = source_published_date or nvd_published_date

            result[cve_id] = {
                "cve_id": cve_id,
                "source_name": source_name,
                "source_record_count": len(rows_sorted),
                "ingest_time": ingest_time,
                "publish_time": self._to_datetime(effective_publish_date),
                "source_publish_time": self._to_datetime(source_published_date),
                "nvd_publish_time": self._to_datetime(nvd_published_date),
                "severity": severity,
                "score": score,
                "source_url": source_url,
                "references": refs,
                "vendors": vendors,
                "products": products,
                "last_modified_date": self._to_datetime(source_last_modified_date),
                "nvd_last_modified_date": self._to_datetime(nvd_last_modified_date),
            }

        return result

    def _calculate_avd_completeness(self, row: dict) -> float:
        # Score how much publishable AVD information exists for one record.
        checks = []

        def add(v):
            checks.append(1.0 if v else 0.0)

        add(bool(row.get("cve_id")))
        add(row.get("ingest_time") is not None)
        add(row.get("publish_time") is not None)
        add(bool(row.get("record_status")))
        add(bool(row.get("assessment_id")))
        add(row.get("base_score") is not None)
        add(bool(row.get("base_severity")))
        add(row.get("final_score") is not None)
        add(bool(row.get("priority_level")))
        add(row.get("exploitation_risk_score") is not None)
        add(row.get("kev_status") is not None)

        kev_status = int(row.get("kev_status") or 0)
        if kev_status == 0:
            add(row.get("epss_score") is not None)
            add(row.get("epss_percentile") is not None)
        else:
            add(bool(row.get("exploitation_risk_source")))
            add(bool(row.get("exploitation_risk_external_id")))
            add(bool(row.get("exploitation_risk_source_url")))

        au_signal_score = float(row.get("au_signal_score") or 0)
        add(row.get("au_signal_score") is not None)
        if au_signal_score != 0:
            add(bool(row.get("au_signal_source")))
            add(bool(row.get("au_signal_external_id")))
            add(bool(row.get("au_signal_source_url")))
            add(bool(row.get("au_signal_label")))

        return safe_divide(sum(checks), len(checks))

    def _calculate_external_completeness(self, row: dict, source: Optional[str] = None) -> float:
        # Score normalized third-party records using source-aware field weights.
        """
        Measure source-agnostic completeness for an external vulnerability database.

        This is deliberately moderate, not source-specific. It evaluates fields that
        any vulnerability database can reasonably expose: CVE identity, source-owned
        dates, CVSS/severity triage data, traceability, and affected asset metadata.

        The calibration is slightly more forgiving than the strict version: a record
        with CVE + source publication date + score/severity + canonical URL should
        land around the high-70s even when affected-asset fields or expanded
        references are sparse. Richer records still score higher.
        """
        weighted_checks = []

        def add(weight: float, score: float):
            weighted_checks.append((weight, max(0.0, min(1.0, float(score)))))

        refs = row.get("references", []) or []
        vendors = self._normalize_list(row.get("vendors"))
        products = self._normalize_list(row.get("products"))
        source_url = row.get("source_url")
        score = row.get("score")
        severity = row.get("severity")

        score_ok = self._score_range_0_10(score) == 1.0
        severity_ok = self._normalize_severity(severity) in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        source_url_ok = bool(source_url and valid_url(str(source_url)))
        source_pub_ok = row.get("source_publish_time") is not None

        # Identity and ingestion metadata.
        add(0.13, 1.0 if row.get("cve_id") and self.CVE_PATTERN.match(str(row.get("cve_id"))) else 0.0)
        add(0.05, 1.0 if row.get("ingest_time") is not None else 0.0)

        # Source-owned temporal metadata. Published date is core; modified date is
        # helpful but not universal, so a record with a source publication date gets
        # partial credit when modified time is unavailable.
        add(0.14, 1.0 if source_pub_ok else 0.0)
        add(0.05, 1.0 if row.get("last_modified_date") is not None else (0.4 if source_pub_ok else 0.0))

        # Triage information. Give small cross-credit when only one of score/severity
        # is available because some feeds derive severity labels from CVSS bands.
        add(0.16, 1.0 if score_ok else (0.45 if severity_ok else 0.0))
        add(0.12, 1.0 if severity_ok else (0.55 if score_ok else 0.0))

        # Affected asset structure. This remains meaningful, but its weight is not
        # dominant because public feeds vary in vendor/product granularity.
        vendor_score = self._score_meaningful_terms(vendors)
        product_score = self._score_meaningful_terms(products)
        has_asset = vendor_score > 0.0 or product_score > 0.0
        add(0.05, vendor_score)
        add(0.05, product_score)
        add(0.03, 1.0 if has_asset else 0.0)

        # Evidence and traceability. A canonical source URL is already meaningful
        # evidence; expanded references add credit but are no longer a hard gate.
        add(0.10, 1.0 if source_url_ok else 0.0)
        add(0.07, max(self._score_references_presence(refs), 0.60 if source_url_ok else 0.0))
        add(0.05, max(self._score_reference_depth(refs), 0.35 if source_url_ok else 0.0))

        total_weight = sum(weight for weight, _ in weighted_checks)
        total_score = sum(weight * score for weight, score in weighted_checks)
        return safe_divide(total_score, total_weight)

    def _score_meaningful_terms(self, values: Any) -> float:
        terms = self._normalize_list(values)
        if not terms:
            return 0.0

        weak_terms = {
            "n a", "na", "none", "unknown", "unspecified", "multiple",
            "various", "not available", "not specified", "vendor", "product",
        }
        meaningful = [t for t in terms if t not in weak_terms and len(t) >= 2]
        if not meaningful:
            return 0.0

        # Cap at 1.0. Two or more meaningful terms usually means the source has
        # useful structure rather than a placeholder.
        return min(1.0, len(meaningful) / 2.0)

    @staticmethod
    def _score_references_presence(refs: Any) -> float:
        if not isinstance(refs, list) or not refs:
            return 0.0
        valid_count = sum(1 for u in refs[:20] if valid_url(str(u)))
        return 1.0 if valid_count >= 1 else 0.0

    @staticmethod
    def _score_reference_depth(refs: Any) -> float:
        if not isinstance(refs, list) or not refs:
            return 0.0
        valid_count = sum(1 for u in refs[:20] if valid_url(str(u)))
        if valid_count >= 3:
            return 1.0
        if valid_count == 2:
            return 0.75
        if valid_count == 1:
            return 0.4
        return 0.0

    def _calculate_accuracy(self, source: str, rows: List[dict], nvd_map: Dict[str, dict]) -> Tuple[float, float]:
        # Compare each source record to its NVD reference and average the weighted
        # structural accuracy scores.
        total_score = 0.0
        total_weight = 0.0

        for row in rows:
            cve_id = row.get("cve_id")
            if not cve_id:
                continue

            nvd_ref = nvd_map.get(cve_id)
            if not nvd_ref:
                continue

            if source == SOURCE_AVD:
                score, weight = self._calculate_avd_accuracy_against_nvd(row, nvd_ref)
            else:
                score, weight = self._calculate_external_accuracy_against_nvd(row, nvd_ref)

            total_score += score
            total_weight += weight

        return total_score, total_weight

    def _calculate_avd_accuracy_against_nvd(self, row: dict, nvd_ref: dict) -> Tuple[float, float]:
        total_score = 0.0
        total_weight = 0.0

        common_fields = {
            "score": self._score_numeric(row.get("base_score"), nvd_ref.get("base_score")),
            "severity": self._score_severity(row.get("base_severity"), nvd_ref.get("severity")),
            "published_date": self._score_date(row.get("nvd_published_date"), nvd_ref.get("published_date")),
            "last_modified_date": self._score_date(row.get("nvd_last_modified_date"), nvd_ref.get("last_modified_date")),
            "vendors": self._score_set(row.get("vendors"), nvd_ref.get("vendors")),
            "products": self._score_set(row.get("product_names"), nvd_ref.get("product_names")),
        }

        for field, score in common_fields.items():
            if score is None:
                continue
            weight = self.COMMON_ACCURACY_WEIGHTS[field]
            total_score += score * weight
            total_weight += weight

        internal_fields = {
            "final_score_formula": self._score_avd_final_formula(row),
            "priority_level": self._score_avd_priority(row),
            "au_signal_source_url": self._score_optional_url(row.get("au_signal_source_url")),
            "exploit_source_url": self._score_optional_url(row.get("exploitation_risk_source_url")),
            "au_signal_external_id": self._score_optional_external_id(row.get("cve_id"), row.get("au_signal_external_id")),
            "exploit_external_id": self._score_optional_external_id(row.get("cve_id"), row.get("exploitation_risk_external_id")),
            "base_score_range": self._score_range_0_10(row.get("base_score")),
            "publication_latency": self._score_avd_publication_latency(
                row.get("ingest_time"),
                row.get("publish_time"),
            ),
        }

        for field, score in internal_fields.items():
            if score is None:
                continue
            weight = self.AVD_INTERNAL_WEIGHTS[field]
            total_score += score * weight
            total_weight += weight

        return total_score, total_weight

    def _calculate_external_accuracy_against_nvd(self, row: dict, nvd_ref: dict) -> Tuple[float, float]:
        total_score = 0.0
        total_weight = 0.0

        common_fields = {
            "score": self._score_numeric(row.get("score"), nvd_ref.get("base_score")),
            "severity": self._score_severity(row.get("severity"), nvd_ref.get("severity")),
            "published_date": self._score_date(row.get("source_publish_time"), nvd_ref.get("published_date")),
            "last_modified_date": self._score_date(row.get("last_modified_date"), nvd_ref.get("last_modified_date")),
            "vendors": self._score_set(row.get("vendors"), nvd_ref.get("vendors")),
            "products": self._score_set(row.get("products"), nvd_ref.get("product_names")),
        }

        for field, score in common_fields.items():
            if score is None:
                continue
            weight = self.COMMON_ACCURACY_WEIGHTS[field]
            total_score += score * weight
            total_weight += weight

        structural_fields = {
            "source_url": self._score_required_url(row.get("source_url")),
            "references": self._score_references(row.get("references")),
        }

        for field, score in structural_fields.items():
            if score is None:
                continue
            weight = self.EXTERNAL_STRUCTURAL_WEIGHTS[field]
            total_score += score * weight
            total_weight += weight

        return total_score, total_weight

    @staticmethod
    def _normalize_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip().lower()
        text = re.sub(r"[_\-]+", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text

    def _normalize_list(self, value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, list):
            items = value
        elif isinstance(value, tuple):
            items = list(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            parsed = from_json_text(text, None)
            if isinstance(parsed, list):
                items = parsed
            else:
                items = re.split(r"[;,|]", text)
        else:
            items = [value]

        cleaned = []
        seen = set()
        for item in items:
            norm = self._normalize_text(item)
            if norm and norm not in seen:
                seen.add(norm)
                cleaned.append(norm)
        return cleaned

    @staticmethod
    def _normalize_severity(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().upper()
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "NONE": "NONE",
        }
        return mapping.get(text, text if text else None)

    def _score_numeric(self, source_value: Any, ref_value: Any) -> Optional[float]:
        if source_value is None or ref_value is None:
            return None
        try:
            s = float(source_value)
            r = float(ref_value)
        except Exception:
            return None

        diff = abs(s - r)
        if diff == 0:
            return 1.0
        if diff <= 0.1:
            return 0.98
        if diff <= 0.3:
            return 0.93
        if diff <= 0.5:
            return 0.85
        if diff <= 1.0:
            return 0.70
        if diff <= 2.0:
            return 0.45
        return 0.0

    def _score_severity(self, source_value: Any, ref_value: Any) -> Optional[float]:
        s = self._normalize_severity(source_value)
        r = self._normalize_severity(ref_value)
        if s is None or r is None:
            return None
        return 1.0 if s == r else 0.0

    def _score_date(self, source_value: Any, ref_value: Any) -> Optional[float]:
        s = self._to_date(source_value)
        r = self._to_date(ref_value)
        if s is None or r is None:
            return None

        delta_days = abs((s - r).days)
        if delta_days == 0:
            return 1.0
        if delta_days <= 3:
            return 0.90
        if delta_days <= 7:
            return 0.75
        if delta_days <= 30:
            return 0.40
        if delta_days <= 90:
            return 0.15
        return 0.0

    def _score_set(self, source_value: Any, ref_value: Any) -> Optional[float]:
        s = set(self._normalize_list(source_value))
        r = set(self._normalize_list(ref_value))
        if not s or not r:
            return None

        inter = len(s & r)
        union = len(s | r)
        if union == 0:
            return None
        return inter / union

    @staticmethod
    def _score_range_0_10(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            f = float(value)
        except Exception:
            return 0.0
        return 1.0 if 0.0 <= f <= 10.0 else 0.0

    @staticmethod
    def _score_optional_url(value: Any) -> Optional[float]:
        if not value:
            return None
        return 1.0 if valid_url(str(value)) else 0.0

    @staticmethod
    def _score_required_url(value: Any) -> Optional[float]:
        if not value:
            return None
        return 1.0 if valid_url(str(value)) else 0.0

    @staticmethod
    def _score_references(refs: Any) -> Optional[float]:
        if not refs:
            return None
        if not isinstance(refs, list):
            return 0.0
        subset = refs[:20]
        if not subset:
            return None
        valid_count = sum(1 for u in subset if valid_url(str(u)))
        return valid_count / len(subset)

    @staticmethod
    def _score_optional_external_id(cve_id: Any, external_id: Any) -> Optional[float]:
        if not external_id:
            return None
        return 1.0 if str(cve_id or "") == str(external_id or "") else 0.0

    def _score_avd_publication_latency(self, ingest_time: Any, publish_time: Any) -> Optional[float]:
        ingest_dt = self._to_datetime(ingest_time)
        publish_dt = self._to_datetime(publish_time)
        if ingest_dt is None or publish_dt is None:
            return None

        delta_minutes = (publish_dt - ingest_dt).total_seconds() / 60.0
        # if delta_minutes < 0:
        #     return 0.0
        # if delta_minutes <= 30:
        #     return 1.0
        # if delta_minutes <= 60:
        #     return 0.85
        # if delta_minutes <= 120:
        #     return 0.65
        # if delta_minutes <= 180:
        #     return 0.45
        # if delta_minutes <= 240:
        #     return 0.25
        # return 0.0
        if delta_minutes < 0:
            return 0.0
        if delta_minutes <= 5:
            return 1.0
        if delta_minutes <= 10:
            return 0.95
        if delta_minutes <= 30:
            return 0.85
        if delta_minutes <= 60:
            return 0.65
        if delta_minutes <= 120:
            return 0.45
        if delta_minutes <= 240:
            return 0.25
        return 0.0

    @staticmethod
    def _score_avd_final_formula(row: dict) -> Optional[float]:
        base_score = row.get("base_score")
        final_score = row.get("final_score")
        exploit = row.get("exploitation_risk_score")
        au = row.get("au_signal_score")

        if None in (base_score, final_score, exploit, au):
            return None

        expected = min(10.0, (0.8 * float(base_score)) + float(exploit) + float(au))
        diff = abs(expected - float(final_score))
        if diff <= 0.01:
            return 1.0
        if diff <= 0.05:
            return 0.8
        if diff <= 0.10:
            return 0.5
        return 0.0

    @staticmethod
    def _score_avd_priority(row: dict) -> Optional[float]:
        final_score = row.get("final_score")
        priority_level = row.get("priority_level")
        if final_score is None or not priority_level:
            return None

        score = float(final_score)
        if score >= 9.0:
            expected = "critical"
        elif score >= 7.0:
            expected = "high"
        elif score >= 4.0:
            expected = "medium"
        else:
            expected = "low"

        return 1.0 if str(priority_level).strip().lower() == expected else 0.0

    @staticmethod
    def _avg(values: List[float]) -> float:
        if not values:
            return 0.0
        return float(sum(values)) / len(values)

    @staticmethod
    def _to_date(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
            except ValueError:
                try:
                    return datetime.strptime(text[:10], "%Y-%m-%d").date()
                except ValueError:
                    return None
        return None

    @staticmethod
    def _to_datetime(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, time.min)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    d = datetime.strptime(text[:10], "%Y-%m-%d").date()
                    return datetime.combine(d, time.min)
                except ValueError:
                    return None
        return None

    def _replace_metrics(self, metrics: List[MetricRow], scenario_years: List[int]) -> None:
        # Delete and rewrite metrics for the requested years so each run leaves one
        # authoritative result set.
        years = tuple(sorted(set(scenario_years)))
        placeholders = ", ".join(["%s"] * len(years))
        delete_sql = f"DELETE FROM {EXPERIMENTAL_TABLE_METRICS} WHERE scenario_year IN ({placeholders})"
        insert_sql = f"""
        INSERT INTO {EXPERIMENTAL_TABLE_METRICS} (
            scenario_year,
            subject_source,
            comparison_source,
            metric_name,
            metric_value,
            numerator_value,
            denominator_value,
            unit,
            note
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        with self.connection.cursor() as cursor:
            cursor.execute(delete_sql, years)
            cursor.executemany(
                insert_sql,
                [
                    (
                        metric.scenario_year,
                        metric.subject_source,
                        metric.comparison_source,
                        metric.metric_name,
                        metric.metric_value,
                        metric.numerator_value,
                        metric.denominator_value,
                        metric.unit,
                        metric.note,
                    )
                    for metric in metrics
                ],
            )