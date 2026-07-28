"""HTTP endpoint tests for the anomalies and compliance APIs."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _register(client: AsyncClient, suffix: str) -> str:
    """Register a unique tenant and return a JWT token."""
    email = f"anomaly_{suffix}@example.com"
    await client.post(
        "/api/v1/auth/register",
        json={"name": "Anomaly Tester", "email": email, "password": "testpass123"},
    )
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": email, "password": "testpass123"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


async def _create_source(
    client: AsyncClient,
    token: str,
    name: str,
    classification: str = "internal",
) -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={
            "name": name,
            "source_type": "directory",
            "path": "/tmp/anom_test",
            "classification": classification,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# Alert listing
# ---------------------------------------------------------------------------


async def test_list_anomalies_empty(client: AsyncClient):
    token = await _register(client, "list_empty")
    resp = await client.get("/api/v1/anomalies", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_anomalies_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/anomalies")
    assert resp.status_code == 401


async def test_source_anomalies_empty(client: AsyncClient):
    token = await _register(client, "src_anom_empty")
    source = await _create_source(client, token, "Source For Anomaly Check")

    resp = await client.get(
        f"/api/v1/anomalies/{source['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_source_anomalies_wrong_source_returns_404(client: AsyncClient):
    token = await _register(client, "wrong_src")
    resp = await client.get(
        "/api/v1/anomalies/99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_source_anomalies_tenant_isolation(client: AsyncClient):
    """Tenant B must not see sources belonging to Tenant A."""
    token_a = await _register(client, "anom_iso_a")
    token_b = await _register(client, "anom_iso_b")

    source = await _create_source(client, token_a, "Tenant A Source")
    resp = await client.get(
        f"/api/v1/anomalies/{source['id']}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Compliance score
# ---------------------------------------------------------------------------


async def test_compliance_score_no_sources(client: AsyncClient):
    token = await _register(client, "score_empty")
    resp = await client.get(
        "/api/v1/anomalies/compliance/score",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] == 100.0
    assert data["source_count"] == 0


async def test_compliance_score_source_without_policy(client: AsyncClient):
    """A source with no policy attached loses 50 SOC 2 points."""
    token = await _register(client, "score_no_policy")
    await _create_source(client, token, "Unpolicied Source")

    resp = await client.get(
        "/api/v1/anomalies/compliance/score",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] == 50.0
    assert data["source_count"] == 1


async def test_compliance_score_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/anomalies/compliance/score")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------


async def test_compliance_report_no_sources(client: AsyncClient):
    token = await _register(client, "report_empty")
    resp = await client.get(
        "/api/v1/anomalies/compliance/report",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_score"] == 100.0
    assert data["total_violations"] == 0
    assert data["critical_alerts"] == 0
    assert data["sources"] == []


async def test_compliance_report_source_without_policy(client: AsyncClient):
    token = await _register(client, "report_no_policy")
    await _create_source(client, token, "Report Source")

    resp = await client.get(
        "/api/v1/anomalies/compliance/report",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Missing policy generates at least the SOC 2 "no policy" violation
    assert data["total_violations"] >= 1
    assert data["overall_score"] < 100.0
    assert len(data["sources"]) == 1


async def test_compliance_report_pii_source_hipaa_violation(client: AsyncClient):
    """A PII source without a policy must flag HIPAA violations in the report."""
    token = await _register(client, "report_pii")
    await _create_source(client, token, "PII Source", classification="pii")

    resp = await client.get(
        "/api/v1/anomalies/compliance/report",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    source_data = data["sources"][0]
    violations = source_data["violations"]
    assert any("HIPAA" in v for v in violations)


async def test_compliance_report_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/anomalies/compliance/report")
    assert resp.status_code == 401
