"""Tests for the reports API endpoints."""

import io


class TestReportsEndpoint:
    def test_empty_reports(self, client):
        response = client.get("/api/reports")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 0
        assert data["reports"] == []

    def test_list_reports_after_scan(self, client, terrible_tf):
        client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        response = client.get("/api/reports")
        data = response.json()
        assert data["total_scans"] == 1
        assert data["reports"][0]["filename"] == "terrible.tf"

    def test_get_single_report(self, client, terrible_tf):
        scan_response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        scan_id = scan_response.json()["scan_id"]

        response = client.get(f"/api/reports/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_report_not_found(self, client):
        response = client.get("/api/reports/999")
        assert response.status_code == 404

    def test_report_findings_have_required_fields(self, client, terrible_tf):
        scan_response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        scan_id = scan_response.json()["scan_id"]

        data = client.get(f"/api/reports/{scan_id}").json()
        finding = data["findings"][0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "resource_type" in finding
        assert "resource_name" in finding
        assert "description" in finding
        assert "remediation" in finding

    def test_reports_ordered_by_newest_first(self, client, terrible_tf, clean_tf):
        client.post("/api/scan", files={"file": ("first.tf", io.BytesIO(clean_tf.encode()), "text/plain")})
        client.post("/api/scan", files={"file": ("second.tf", io.BytesIO(terrible_tf.encode()), "text/plain")})

        data = client.get("/api/reports").json()
        assert data["reports"][0]["filename"] == "second.tf"
        assert data["reports"][1]["filename"] == "first.tf"
