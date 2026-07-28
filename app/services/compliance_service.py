"""
Compliance scoring service.

Maps policy attributes and source configuration to framework controls:

  SOC 2  — encryption (checksum), retention >= 30d, RPO <= 1440 min, audit log
  HIPAA  — applies only to PII classification; requires checksum + dedup + 365d retention
  PCI-DSS — applies only to financial classification; 365d retention + daily backups

Each framework starts at 100 points; violations deduct a fixed amount.
The overall score is the average of all applicable framework scores.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Per-source scoring
# ---------------------------------------------------------------------------


def score_source_compliance(
    source: Any,
    policy: Optional[Any],
    last_snapshot: Optional[Any],
    alerts: list[Any],
) -> dict:
    """
    Returns a dict matching the ComplianceScore schema fields.

    Parameters
    ----------
    source      : DataSource ORM object
    policy      : BackupPolicy ORM object (or None if no policy attached)
    last_snapshot : BackupSnapshot ORM object (or None)
    alerts      : list of AnomalyAlert ORM objects for this source
    """
    violations: list[str] = []
    soc2 = 100.0
    hipaa = 100.0
    pci = 100.0

    has_policy = policy is not None
    classification = source.classification.value if hasattr(source.classification, "value") else str(source.classification)

    # ------------------------------------------------------------------
    # SOC 2 controls
    # ------------------------------------------------------------------
    if not has_policy:
        soc2 -= 50.0
        violations.append("SOC 2: No backup policy attached")
    else:
        if policy.retention_days < 30:
            soc2 -= 25.0
            violations.append(
                f"SOC 2: Retention {policy.retention_days}d is below the 30-day minimum"
            )
        if not policy.require_checksum:
            soc2 -= 25.0
            violations.append("SOC 2: Checksum verification is not required by policy")
        if policy.rpo_minutes > 1440:
            soc2 -= 25.0
            violations.append(
                f"SOC 2: RPO {policy.rpo_minutes} min exceeds the 1440-min (24h) limit"
            )

    critical_alerts = [a for a in alerts if hasattr(a, "severity") and str(a.severity) in ("critical", "AlertSeverity.critical")]
    if critical_alerts:
        soc2 -= 25.0
        violations.append(
            f"SOC 2: {len(critical_alerts)} critical alert(s) unresolved"
        )

    soc2 = max(0.0, soc2)

    # ------------------------------------------------------------------
    # HIPAA controls (PII data only)
    # ------------------------------------------------------------------
    hipaa_applicable = classification in ("pii",)
    if hipaa_applicable:
        if not has_policy:
            hipaa -= 100.0
            violations.append("HIPAA: PII source has no backup policy")
        else:
            if not policy.require_checksum:
                hipaa -= 33.0
                violations.append("HIPAA: PII source requires encryption (checksum) per policy")
            if not policy.require_dedup:
                hipaa -= 33.0
                violations.append("HIPAA: PII source requires deduplication per policy")
            if policy.retention_days < 365:
                hipaa -= 34.0
                violations.append(
                    f"HIPAA: PII source retention {policy.retention_days}d is below 365-day minimum"
                )
    hipaa = max(0.0, hipaa)

    # ------------------------------------------------------------------
    # PCI-DSS controls (financial data only)
    # ------------------------------------------------------------------
    pci_applicable = classification in ("financial",)
    if pci_applicable:
        if not has_policy:
            pci -= 100.0
            violations.append("PCI-DSS: Financial source has no backup policy")
        else:
            if policy.retention_days < 365:
                pci -= 50.0
                violations.append(
                    f"PCI-DSS: Financial source retention {policy.retention_days}d is below 365-day minimum"
                )
            if policy.frequency_minutes > 1440:
                pci -= 50.0
                violations.append(
                    f"PCI-DSS: Financial source backup frequency {policy.frequency_minutes} min exceeds 1440 min (not daily)"
                )
    pci = max(0.0, pci)

    # ------------------------------------------------------------------
    # Overall score — average of applicable frameworks
    # ------------------------------------------------------------------
    applicable_scores = [soc2]
    if hipaa_applicable:
        applicable_scores.append(hipaa)
    if pci_applicable:
        applicable_scores.append(pci)
    overall = sum(applicable_scores) / len(applicable_scores)

    return {
        "source_id": source.id,
        "source_name": source.name,
        "overall_score": round(overall, 2),
        "soc2_score": round(soc2, 2),
        "hipaa_score": round(hipaa, 2),
        "pci_score": round(pci, 2),
        "violations": violations,
        "last_evaluated": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Tenant-level report
# ---------------------------------------------------------------------------


def generate_report(
    tenant_id: int,
    source_scores: list[dict],
    alerts: list[Any],
) -> dict:
    """
    Aggregate per-source scores into a ComplianceReport.

    Parameters
    ----------
    tenant_id     : int
    source_scores : list of dicts returned by score_source_compliance
    alerts        : all AnomalyAlert objects for the tenant
    """
    if not source_scores:
        overall = 100.0
    else:
        overall = sum(s["overall_score"] for s in source_scores) / len(source_scores)

    total_violations = sum(len(s["violations"]) for s in source_scores)
    critical_count = sum(
        1
        for a in alerts
        if hasattr(a, "severity") and str(a.severity) in ("critical", "AlertSeverity.critical")
        and not a.resolved
    )

    return {
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc),
        "overall_score": round(overall, 2),
        "sources": source_scores,
        "total_violations": total_violations,
        "critical_alerts": critical_count,
    }
