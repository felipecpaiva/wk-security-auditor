"""Tests for the scan API endpoint."""

import io


class TestScanEndpoint:
    def test_scan_terraform_file(self, client, terrible_tf):
        response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "terrible.tf"
        assert data["file_type"] == "terraform"
        assert data["risk_score"] > 0
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_scan_clean_file(self, client, clean_tf):
        response = client.post(
            "/api/scan",
            files={"file": ("clean.tf", io.BytesIO(clean_tf.encode()), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 0.0
        assert data["total_findings"] == 0

    def test_scan_cloudformation_yaml(self, client, bad_cf_yaml):
        response = client.post(
            "/api/scan",
            files={"file": ("stack.cfn.yaml", io.BytesIO(bad_cf_yaml.encode()), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["file_type"] == "cloudformation"
        assert data["total_findings"] > 0

    def test_scan_returns_severity_breakdown(self, client, terrible_tf):
        response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        data = response.json()
        assert "severity_breakdown" in data
        assert "critical" in data["severity_breakdown"]
        assert "high" in data["severity_breakdown"]

    def test_scan_persists_to_database(self, client, terrible_tf):
        client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        reports = client.get("/api/reports").json()
        assert reports["total_scans"] == 1

    def test_multiple_scans_accumulate(self, client, terrible_tf, clean_tf):
        client.post("/api/scan", files={"file": ("a.tf", io.BytesIO(terrible_tf.encode()), "text/plain")})
        client.post("/api/scan", files={"file": ("b.tf", io.BytesIO(clean_tf.encode()), "text/plain")})
        reports = client.get("/api/reports").json()
        assert reports["total_scans"] == 2
