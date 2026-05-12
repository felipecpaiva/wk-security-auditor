"""Scan API — upload and audit infrastructure config files."""

from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Scan, Finding
from app.engine.auditor import run_audit

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan")
async def create_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    content_str = content.decode("utf-8")

    result = run_audit(file.filename or "unknown.tf", content_str)

    scan = Scan(
        filename=file.filename or "unknown",
        file_type=result["file_type"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        total_findings=result["total_findings"],
        critical_count=result["critical_count"],
        high_count=result["high_count"],
        medium_count=result["medium_count"],
        low_count=result["low_count"],
    )
    db.add(scan)
    db.flush()

    for f in result["findings"]:
        finding = Finding(
            scan_id=scan.id,
            rule_id=f.rule_id,
            severity=f.severity,
            resource_type=f.resource_type,
            resource_name=f.resource_name,
            description=f.description,
            remediation=f.remediation,
        )
        db.add(finding)

    db.commit()
    db.refresh(scan)

    return {
        "scan_id": scan.id,
        "filename": scan.filename,
        "file_type": scan.file_type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "total_findings": scan.total_findings,
        "severity_breakdown": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
        },
        "findings": [f.to_dict() for f in scan.findings],
    }
