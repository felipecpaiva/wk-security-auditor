"""Tests for the reports API endpoints.

Covers: GET /api/reports, GET /api/reports/{id}.
"""

import io


class TestReportsEndpoint:
    def test_list_reports_empty(self, client):
        """Fresh DB → total_scans=0, empty list."""
        response = client.get("/api/reports")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 0
        assert data["reports"] == []

    def test_list_reports_after_scans(self, client, terrible_tf, clean_tf):
        """Upload 2 files → total_scans=2."""
        client.post("/api/scan", files={"file": ("a.tf", io.BytesIO(terrible_tf.encode()), "text/plain")})
        client.post("/api/scan", files={"file": ("b.tf", io.BytesIO(clean_tf.encode()), "text/plain")})
        data = client.get("/api/reports").json()
        assert data["total_scans"] == 2

    def test_get_report_detail(self, client, terrible_tf):
        """Upload file → GET by ID → has findings."""
        scan = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        ).json()
        scan_id = scan["scan_id"]

        response = client.get(f"/api/reports/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id
        assert "findings" in data

    def test_get_report_not_found(self, client):
        """GET /api/reports/99999 → 404."""
        response = client.get("/api/reports/99999")
        assert response.status_code == 404

    def test_get_report_includes_findings(self, client, terrible_tf):
        """terrible.tf → 13 findings in detail response, each with required fields."""
        scan = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        ).json()

        data = client.get(f"/api/reports/{scan['scan_id']}").json()
        assert len(data["findings"]) == 13
        finding = data["findings"][0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "resource_type" in finding
        assert "resource_name" in finding
        assert "description" in finding
        assert "remediation" in finding

    def test_reports_ordered_by_date(self, client, terrible_tf, clean_tf):
        """Most recent scan appears first."""
        client.post("/api/scan", files={"file": ("first.tf", io.BytesIO(clean_tf.encode()), "text/plain")})
        client.post("/api/scan", files={"file": ("second.tf", io.BytesIO(terrible_tf.encode()), "text/plain")})

        data = client.get("/api/reports").json()
        assert data["reports"][0]["filename"] == "second.tf"
        assert data["reports"][1]["filename"] == "first.tf"
