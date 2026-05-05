from decimal import Decimal, ROUND_HALF_UP
import uuid

from app.config import DB_TABLE_AVD_ASSESSMENTS
from app.services.au_signal_enricher import AUSignalEnricher
from app.services.exploitation_risk_enricher import ExploitationRiskEnricher


class AssessmentService:
    def __init__(self, connection):
        self.connection = connection
        self.au_signal_enricher = AUSignalEnricher()
        self.exploitation_risk_enricher = ExploitationRiskEnricher()
 
    def calculate_score(
        self,
        base_score,
        exploitation_risk_score,
        au_signal_score,
    ) -> Decimal:
        # Blend CVSS severity with Australian relevance and exploitation evidence
        # to produce the project-specific final AVD priority score.
        base = Decimal(str(base_score if base_score is not None else 0))
        exploit = Decimal(str(exploitation_risk_score if exploitation_risk_score is not None else 0))
        au_signal = Decimal(str(au_signal_score if au_signal_score is not None else 0))

        raw = (Decimal("0.8") * base) + exploit + au_signal
        final_score = min(Decimal("10.00"), raw)
        return final_score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def get_priority_level(self, final_score: Decimal) -> str:
        # Convert the numeric final score into the priority bands shown in the web UI.
        score = float(final_score)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    def generate_assessment_id(self) -> str:
        return f"ASMT_{uuid.uuid4().hex[:25]}"

    def create_assessment(self, cve_id: str, base_score, base_severity) -> str:
        # Enrichment services add exploitation and Australian-context signals before
        # the assessment row is written to the database.
        assessment_id = self.generate_assessment_id()

        exploitation = self.exploitation_risk_enricher.get_exploitation_risk_result(cve_id)
        au_signal = self.au_signal_enricher.get_signal_result(cve_id)

        final_score = self.calculate_score(
            base_score,
            exploitation["exploitation_risk_score"],
            au_signal["au_signal_score"],
        )
        priority_level = self.get_priority_level(final_score)

        sql = f"""
        INSERT INTO {DB_TABLE_AVD_ASSESSMENTS} (
            assessment_id,
            cve_id,
            base_score,
            base_severity,

            exploitation_risk_score,
            exploitation_risk_source,
            exploitation_risk_external_id,
            exploitation_risk_source_url,

            kev_status,
            epss_score,
            epss_percentile,

            au_signal_score,
            au_signal_source,
            au_signal_external_id,
            au_signal_source_url,
            au_signal_label,

            final_score,
            priority_level,
            assessed_at
        ) VALUES (
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, NOW()
        )
        """

        with self.connection.cursor() as cursor:
            cursor.execute(
                sql,
                (
                    assessment_id,
                    cve_id,
                    base_score,
                    base_severity,

                    exploitation["exploitation_risk_score"],
                    exploitation["exploitation_risk_source"],
                    exploitation["exploitation_risk_external_id"],
                    exploitation["exploitation_risk_source_url"],

                    exploitation["kev_status"],
                    exploitation["epss_score"],
                    exploitation["epss_percentile"],

                    au_signal["au_signal_score"],
                    au_signal["au_signal_source"],
                    au_signal["au_signal_external_id"],
                    au_signal["au_signal_source_url"],
                    au_signal["au_signal_label"],

                    final_score,
                    priority_level,
                ),
            )

        return assessment_id