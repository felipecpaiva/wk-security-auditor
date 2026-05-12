"""Tests for the scan API endpoint.

Covers: POST /api/scan with various file types, response schema, persistence.
"""

import io


class TestScanEndpoint:
    def test_scan_upload_terraform(self, client, clean_tf):
        """POST clean.tf → 200, risk_score=0.0."""
        response = client.post(
            "/api/scan",
            files={"file": ("clean.tf", io.BytesIO(clean_tf.encode()), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 0.0
        assert data["file_type"] == "terraform"

    def test_scan_upload_cloudformation(self, client, bad_cf_yaml):
        """POST bad CF → 200, risk_level=Critical."""
        response = client.post(
            "/api/scan",
            files={"file": ("stack.cfn.yaml", io.BytesIO(bad_cf_yaml.encode()), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["file_type"] == "cloudformation"
        assert data["risk_level"] == "Critical"

    def test_scan_returns_findings(self, client, terrible_tf):
        """POST terrible.tf → 13 findings in response."""
        response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        data = response.json()
        assert len(data["findings"]) == 13
        assert data["total_findings"] == 13

    def test_scan_persists_to_db(self, client, terrible_tf):
        """POST file → GET /api/reports shows 1 entry."""
        client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        reports = client.get("/api/reports").json()
        assert reports["total_scans"] == 1
        assert reports["reports"][0]["filename"] == "terrible.tf"

    def test_scan_response_schema(self, client, terrible_tf):
        """Response has all expected top-level keys."""
        response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        data = response.json()
        expected_keys = {"scan_id", "filename", "file_type", "risk_score",
                         "risk_level", "total_findings", "severity_breakdown", "findings"}
        assert expected_keys.issubset(set(data.keys()))

    def test_scan_severity_breakdown(self, client, terrible_tf):
        """severity_breakdown has critical/high/medium/low keys."""
        response = client.post(
            "/api/scan",
            files={"file": ("terrible.tf", io.BytesIO(terrible_tf.encode()), "text/plain")},
        )
        breakdown = response.json()["severity_breakdown"]
        assert "critical" in breakdown
        assert "high" in breakdown
        assert "medium" in breakdown
        assert "low" in breakdown
        assert breakdown["critical"] == 5
        assert breakdown["high"] == 6

    def test_scan_empty_file(self, client):
        """POST empty .tf → 200, 0 findings."""
        response = client.post(
            "/api/scan",
            files={"file": ("empty.tf", io.BytesIO(b""), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_findings"] == 0
        assert data["risk_score"] == 0.0

    def test_scan_filename_preserved(self, client, clean_tf):
        """Uploaded filename appears in response."""
        response = client.post(
            "/api/scan",
            files={"file": ("my-infra.tf", io.BytesIO(clean_tf.encode()), "text/plain")},
        )
        assert response.json()["filename"] == "my-infra.tf"
