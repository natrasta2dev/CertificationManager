"""Tests d'intégration API."""

import pytest


class TestAPIIntegration:
  """Tests des endpoints REST."""

  def test_health_statistics(self, api_client):
      response = api_client.get("/api/statistics")
      assert response.status_code == 200
      data = response.json()
      assert data["success"] is True
      assert "total" in data["data"]

  def test_create_and_list_certificate(self, api_client):
      create = api_client.post(
          "/api/certificates",
          json={
              "common_name": "api.example.com",
              "validity_days": 365,
              "organization": "API Test",
          },
      )
      assert create.status_code == 200
      cert_id = create.json()["data"]["id"]

      listing = api_client.get("/api/certificates")
      assert listing.status_code == 200
      body = listing.json()
      ids = [c["id"] for c in body["data"]]
      assert cert_id in ids
      assert "pagination" in body
      assert body["pagination"]["total"] >= 1

  def test_certificates_pagination(self, api_client):
      response = api_client.get("/api/certificates?page=1&limit=5&status=valid")
      assert response.status_code == 200
      data = response.json()
      assert data["success"] is True
      assert "pagination" in data
      assert data["pagination"]["limit"] == 5

  def test_archives_endpoint(self, api_client):
      response = api_client.get("/api/archives")
      assert response.status_code == 200
      assert response.json()["success"] is True
      assert isinstance(response.json()["data"], list)

  def test_compliance_scan(self, api_client):
      response = api_client.get("/api/compliance/scan")
      assert response.status_code == 200
      data = response.json()["data"]
      assert "compliance_rate" in data
      assert "issues_count" in data

  def test_metrics_endpoint(self, api_client):
      response = api_client.get("/api/metrics")
      assert response.status_code == 200
      assert "certmanager_certificates_total" in response.text

  def test_config_summary(self, api_client):
      response = api_client.get("/api/config")
      assert response.status_code == 200
      assert "storage_path" in response.json()["data"]

  def test_letsencrypt_obtain_accepts_json_body(self, api_client):
      response = api_client.post(
          "/api/letsencrypt/obtain",
          json={"domains": ["test.example.com"], "staging": True},
      )
      # 503 si certbot absent, 400 si erreur certbot, jamais 422
      assert response.status_code != 422

  def test_auth_login_when_disabled(self, api_client):
      response = api_client.post(
          "/api/auth/login",
          data={"username": "admin", "password": "wrong"},
      )
      assert response.status_code == 400

  def test_api_v1_statistics(self, api_client):
      response = api_client.get("/api/v1/statistics")
      assert response.status_code == 200
      assert response.json()["success"] is True

  def test_bulk_delete(self, api_client):
      create = api_client.post(
          "/api/certificates",
          json={"common_name": "bulk-delete.test", "validity_days": 30},
      )
      cert_id = create.json()["data"]["id"]
      response = api_client.post(
          "/api/v1/certificates/bulk-delete",
          json={"cert_ids": [cert_id]},
      )
      assert response.status_code == 200
      body = response.json()
      assert cert_id in body["data"]["deleted"]

  def test_compliance_dashboard(self, api_client):
      response = api_client.get("/api/compliance/dashboard")
      assert response.status_code == 200
      data = response.json()["data"]
      assert "guidelines" in data

  def test_compliance_pdf(self, api_client):
      response = api_client.get("/api/v1/reports/compliance.pdf")
      assert response.status_code == 200
      assert response.headers["content-type"].startswith("application/pdf")
      assert response.content.startswith(b"%PDF")
