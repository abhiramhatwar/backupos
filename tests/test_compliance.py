"""Unit tests for the compliance scoring service (no database required)."""
from types import SimpleNamespace

import pytest

from app.services.compliance_service import generate_report, score_source_compliance


def _source(classification="internal"):
    return SimpleNamespace(id=1, name="Test Source", classification=classification)


def _policy(
    retention_days=30,
    require_checksum=True,
    require_dedup=True,
    rpo_minutes=1440,
    frequency_minutes=1440,
):
    return SimpleNamespace(
        retention_days=retention_days,
        require_checksum=require_checksum,
        require_dedup=require_dedup,
        rpo_minutes=rpo_minutes,
        frequency_minutes=frequency_minutes,
    )


def _alert(severity="critical", resolved=False):
    return SimpleNamespace(severity=severity, resolved=resolved)


class TestSOC2Scoring:
    def test_compliant_policy_scores_100(self):
        result = score_source_compliance(_source(), _policy(), None, [])
        assert result["soc2_score"] == 100.0
        assert result["violations"] == []

    def test_no_policy_deducts_50(self):
        result = score_source_compliance(_source(), None, None, [])
        assert result["soc2_score"] == 50.0
        assert any("No backup policy" in v for v in result["violations"])

    def test_retention_below_30d_deducts_25(self):
        result = score_source_compliance(_source(), _policy(retention_days=7), None, [])
        assert result["soc2_score"] == 75.0
        assert any("Retention" in v and "30-day" in v for v in result["violations"])

    def test_no_checksum_deducts_25(self):
        result = score_source_compliance(_source(), _policy(require_checksum=False), None, [])
        assert result["soc2_score"] == 75.0

    def test_rpo_over_1440_deducts_25(self):
        result = score_source_compliance(_source(), _policy(rpo_minutes=2880), None, [])
        assert result["soc2_score"] == 75.0

    def test_critical_alert_deducts_25(self):
        alerts = [_alert("critical")]
        result = score_source_compliance(_source(), _policy(), None, alerts)
        assert result["soc2_score"] == 75.0
        assert any("critical alert" in v for v in result["violations"])

    def test_non_critical_alert_no_deduction(self):
        alerts = [_alert("high")]
        result = score_source_compliance(_source(), _policy(), None, alerts)
        assert result["soc2_score"] == 100.0

    def test_multiple_violations_stack(self):
        alerts = [_alert("critical")]
        result = score_source_compliance(
            _source(),
            _policy(retention_days=7, require_checksum=False, rpo_minutes=2880),
            None,
            alerts,
        )
        assert result["soc2_score"] == 0.0

    def test_soc2_floor_is_zero(self):
        alerts = [_alert("critical")] * 10
        result = score_source_compliance(
            _source(),
            _policy(retention_days=1, require_checksum=False, rpo_minutes=99999),
            None,
            alerts,
        )
        assert result["soc2_score"] >= 0.0

    def test_rpo_exactly_at_limit_no_deduction(self):
        result = score_source_compliance(_source(), _policy(rpo_minutes=1440), None, [])
        assert result["soc2_score"] == 100.0


class TestHIPAAScoring:
    def test_not_applicable_for_internal_classification(self):
        result = score_source_compliance(_source("internal"), _policy(), None, [])
        assert result["hipaa_score"] == 100.0
        assert result["overall_score"] == result["soc2_score"]

    def test_pii_no_policy_zeroes_hipaa(self):
        result = score_source_compliance(_source("pii"), None, None, [])
        assert result["hipaa_score"] == 0.0

    def test_pii_retention_below_365_deducts_34(self):
        result = score_source_compliance(
            _source("pii"), _policy(retention_days=90, require_checksum=True, require_dedup=True), None, []
        )
        assert result["hipaa_score"] == pytest.approx(66.0)

    def test_pii_no_checksum_deducts_33(self):
        result = score_source_compliance(
            _source("pii"), _policy(require_checksum=False, retention_days=365), None, []
        )
        assert result["hipaa_score"] == pytest.approx(67.0)

    def test_pii_no_dedup_deducts_33(self):
        result = score_source_compliance(
            _source("pii"), _policy(require_dedup=False, retention_days=365), None, []
        )
        assert result["hipaa_score"] == pytest.approx(67.0)

    def test_pii_fully_compliant_scores_100(self):
        result = score_source_compliance(_source("pii"), _policy(retention_days=365), None, [])
        assert result["hipaa_score"] == 100.0

    def test_pii_overall_averages_soc2_and_hipaa(self):
        result = score_source_compliance(
            _source("pii"), _policy(retention_days=90), None, []
        )
        expected_overall = (result["soc2_score"] + result["hipaa_score"]) / 2
        assert result["overall_score"] == pytest.approx(expected_overall)

    def test_hipaa_floor_is_zero(self):
        result = score_source_compliance(
            _source("pii"),
            _policy(require_checksum=False, require_dedup=False, retention_days=1),
            None,
            [],
        )
        assert result["hipaa_score"] >= 0.0


class TestPCIScoring:
    def test_not_applicable_for_internal(self):
        result = score_source_compliance(_source("internal"), _policy(), None, [])
        assert result["pci_score"] == 100.0
        assert result["overall_score"] == result["soc2_score"]

    def test_financial_no_policy_zeroes_pci(self):
        result = score_source_compliance(_source("financial"), None, None, [])
        assert result["pci_score"] == 0.0

    def test_financial_retention_below_365_deducts_50(self):
        result = score_source_compliance(
            _source("financial"), _policy(retention_days=90), None, []
        )
        assert result["pci_score"] == 50.0

    def test_financial_frequency_over_1440_deducts_50(self):
        result = score_source_compliance(
            _source("financial"), _policy(frequency_minutes=2880, retention_days=365), None, []
        )
        assert result["pci_score"] == 50.0

    def test_financial_fully_compliant(self):
        result = score_source_compliance(
            _source("financial"), _policy(retention_days=365), None, []
        )
        assert result["pci_score"] == 100.0

    def test_financial_overall_averages_soc2_and_pci(self):
        result = score_source_compliance(
            _source("financial"), _policy(retention_days=90), None, []
        )
        expected_overall = (result["soc2_score"] + result["pci_score"]) / 2
        assert result["overall_score"] == pytest.approx(expected_overall)


class TestGenerateReport:
    def test_empty_sources_returns_100(self):
        report = generate_report(tenant_id=1, source_scores=[], alerts=[])
        assert report["overall_score"] == 100.0
        assert report["total_violations"] == 0
        assert report["critical_alerts"] == 0

    def test_aggregates_scores(self):
        scores = [
            {"overall_score": 80.0, "violations": ["v1", "v2"]},
            {"overall_score": 60.0, "violations": ["v3"]},
        ]
        report = generate_report(tenant_id=1, source_scores=scores, alerts=[])
        assert report["overall_score"] == pytest.approx(70.0)
        assert report["total_violations"] == 3

    def test_counts_unresolved_critical_alerts(self):
        alerts = [
            _alert("critical", resolved=False),
            _alert("critical", resolved=True),
            _alert("high", resolved=False),
        ]
        report = generate_report(tenant_id=1, source_scores=[], alerts=alerts)
        assert report["critical_alerts"] == 1

    def test_resolved_critical_alerts_not_counted(self):
        alerts = [_alert("critical", resolved=True)]
        report = generate_report(tenant_id=1, source_scores=[], alerts=alerts)
        assert report["critical_alerts"] == 0

    def test_tenant_id_preserved(self):
        report = generate_report(tenant_id=42, source_scores=[], alerts=[])
        assert report["tenant_id"] == 42

    def test_sources_list_preserved(self):
        scores = [{"overall_score": 75.0, "violations": ["v1"]}]
        report = generate_report(tenant_id=1, source_scores=scores, alerts=[])
        assert report["sources"] == scores
