from __future__ import annotations

import json
import sqlite3
from typing import Any
from uuid import uuid4

from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import utc_now


class FindingRepository:
    """Store and retrieve correlated forensic findings."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create_finding(
        self,
        *,
        analysis_run_id: str,
        finding_code: str,
        title: str,
        summary: str,
        severity: str,
        risk_score: float,
        process_id: str | None = None,
        confidence: str = "medium",
        completeness: str = "complete",
        observed_evidence: str | None = None,
        inferred_explanation: str | None = None,
        benign_explanations: str | None = None,
        counter_evidence: str | None = None,
        limitations: str | None = None,
    ) -> str:
        """Create a forensic finding and return its UUID."""
        finding_id = str(uuid4())
        timestamp = utc_now()

        self.database.execute(
            """
            INSERT INTO findings (
                id,
                analysis_run_id,
                process_id,
                finding_code,
                title,
                summary,
                severity,
                risk_score,
                confidence,
                completeness,
                status,
                observed_evidence,
                inferred_explanation,
                benign_explanations,
                counter_evidence,
                limitations,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                analysis_run_id,
                process_id,
                finding_code,
                title,
                summary,
                severity,
                risk_score,
                confidence,
                completeness,
                "open",
                observed_evidence,
                inferred_explanation,
                benign_explanations,
                counter_evidence,
                limitations,
                timestamp,
                timestamp,
            ),
        )

        return finding_id

    def get_finding(self, finding_id: str) -> sqlite3.Row | None:
        """Return a finding by UUID."""
        return self.database.fetch_one(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        )

    def list_findings(
        self,
        analysis_run_id: str,
        *,
        severity: str | None = None,
        status: str | None = None,
        process_id: str | None = None,
    ) -> list[sqlite3.Row]:
        """List findings using common filters."""
        conditions = ["analysis_run_id = ?"]
        parameters: list[Any] = [analysis_run_id]

        if severity is not None:
            conditions.append("severity = ?")
            parameters.append(severity)

        if status is not None:
            conditions.append("status = ?")
            parameters.append(status)

        if process_id is not None:
            conditions.append("process_id = ?")
            parameters.append(process_id)

        where_clause = " AND ".join(conditions)

        return self.database.fetch_all(
            f"""
            SELECT *
            FROM findings
            WHERE {where_clause}
            ORDER BY risk_score DESC, created_at
            """,
            tuple(parameters),
        )

    def update_finding_status(
        self,
        finding_id: str,
        status: str,
    ) -> bool:
        """Mark a finding as reviewed, accepted, dismissed, or false positive."""
        affected = self.database.execute(
            """
            UPDATE findings
            SET status = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, utc_now(), finding_id),
        )

        return affected > 0

    def update_finding_assessment(
        self,
        finding_id: str,
        *,
        severity: str,
        risk_score: float,
        confidence: str,
        completeness: str,
    ) -> bool:
        """Update the calculated assessment of a finding."""
        affected = self.database.execute(
            """
            UPDATE findings
            SET
                severity = ?,
                risk_score = ?,
                confidence = ?,
                completeness = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                severity,
                risk_score,
                confidence,
                completeness,
                utc_now(),
                finding_id,
            ),
        )

        return affected > 0

    def add_rule_contribution(
        self,
        *,
        finding_id: str,
        rule_id: str,
        rule_name: str,
        score_contribution: float,
        explanation: str,
        rule_definition_id: str | None = None,
        confidence: float | None = None,
        supporting_artifact_ids: list[str] | None = None,
        counter_evidence_ids: list[str] | None = None,
    ) -> str:
        """Add one rule contribution to a finding."""
        contribution_id = str(uuid4())

        self.database.execute(
            """
            INSERT INTO rule_contributions (
                id,
                finding_id,
                rule_definition_id,
                rule_id,
                rule_name,
                score_contribution,
                confidence,
                explanation,
                supporting_artifact_ids_json,
                counter_evidence_ids_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                contribution_id,
                finding_id,
                rule_definition_id,
                rule_id,
                rule_name,
                score_contribution,
                confidence,
                explanation,
                json.dumps(supporting_artifact_ids or []),
                json.dumps(counter_evidence_ids or []),
            ),
        )

        return contribution_id

    def list_rule_contributions(
        self,
        finding_id: str,
    ) -> list[sqlite3.Row]:
        """Return all rule contributions for a finding."""
        return self.database.fetch_all(
            """
            SELECT *
            FROM rule_contributions
            WHERE finding_id = ?
            ORDER BY score_contribution DESC
            """,
            (finding_id,),
        )

    def link_artifact(
        self,
        *,
        finding_id: str,
        artifact_id: str,
        artifact_type: str,
        evidence_role: str,
        description: str | None = None,
    ) -> None:
        """Link supporting, contradicting, contextual, or affected evidence."""
        self.database.execute(
            """
            INSERT OR IGNORE INTO finding_artifacts (
                finding_id,
                artifact_id,
                artifact_type,
                evidence_role,
                description
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                artifact_id,
                artifact_type,
                evidence_role,
                description,
            ),
        )

    def list_finding_artifacts(
        self,
        finding_id: str,
        *,
        evidence_role: str | None = None,
    ) -> list[sqlite3.Row]:
        """Return artifacts associated with a finding."""
        if evidence_role is not None:
            return self.database.fetch_all(
                """
                SELECT *
                FROM finding_artifacts
                WHERE finding_id = ?
                  AND evidence_role = ?
                """,
                (finding_id, evidence_role),
            )

        return self.database.fetch_all(
            """
            SELECT *
            FROM finding_artifacts
            WHERE finding_id = ?
            """,
            (finding_id,),
        )

    def create_finding_with_contributions(
        self,
        *,
        finding_data: dict[str, Any],
        contributions: list[dict[str, Any]],
        artifact_links: list[dict[str, Any]],
    ) -> str:
        """Create a finding and its evidence links atomically."""
        finding_id = str(uuid4())
        timestamp = utc_now()

        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO findings (
                    id,
                    analysis_run_id,
                    process_id,
                    finding_code,
                    title,
                    summary,
                    severity,
                    risk_score,
                    confidence,
                    completeness,
                    status,
                    observed_evidence,
                    inferred_explanation,
                    benign_explanations,
                    counter_evidence,
                    limitations,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    finding_data["analysis_run_id"],
                    finding_data.get("process_id"),
                    finding_data["finding_code"],
                    finding_data["title"],
                    finding_data["summary"],
                    finding_data["severity"],
                    finding_data["risk_score"],
                    finding_data.get("confidence", "medium"),
                    finding_data.get("completeness", "complete"),
                    "open",
                    finding_data.get("observed_evidence"),
                    finding_data.get("inferred_explanation"),
                    finding_data.get("benign_explanations"),
                    finding_data.get("counter_evidence"),
                    finding_data.get("limitations"),
                    timestamp,
                    timestamp,
                ),
            )

            for item in contributions:
                connection.execute(
                    """
                    INSERT INTO rule_contributions (
                        id,
                        finding_id,
                        rule_definition_id,
                        rule_id,
                        rule_name,
                        score_contribution,
                        confidence,
                        explanation,
                        supporting_artifact_ids_json,
                        counter_evidence_ids_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid4()),
                        finding_id,
                        item.get("rule_definition_id"),
                        item["rule_id"],
                        item["rule_name"],
                        item["score_contribution"],
                        item.get("confidence"),
                        item["explanation"],
                        json.dumps(item.get("supporting_artifact_ids", [])),
                        json.dumps(item.get("counter_evidence_ids", [])),
                    ),
                )

            for item in artifact_links:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO finding_artifacts (
                        finding_id,
                        artifact_id,
                        artifact_type,
                        evidence_role,
                        description
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        item["artifact_id"],
                        item["artifact_type"],
                        item["evidence_role"],
                        item.get("description"),
                    ),
                )

        return finding_id

    def count_findings_by_severity(
        self,
        analysis_run_id: str,
    ) -> dict[str, int]:
        """Return dashboard totals grouped by severity."""
        rows = self.database.fetch_all(
            """
            SELECT severity, COUNT(*) AS count
            FROM findings
            WHERE analysis_run_id = ?
            GROUP BY severity
            """,
            (analysis_run_id,),
        )

        return {
            str(row["severity"]): int(row["count"])
            for row in rows
        }

    def delete_findings_for_run(self, analysis_run_id: str) -> int:
        """
        Delete generated findings before re-running correlation.

        Normalized artifacts and raw plugin outputs remain unchanged.
        """
        return self.database.execute(
            "DELETE FROM findings WHERE analysis_run_id = ?",
            (analysis_run_id,),
        )