"""Reports API — list and retrieve scan reports."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Scan

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.scanned_at.desc()).all()
    return {
        "total_scans": len(scans),
        "reports": [s.to_dict() for s in scans],
    }


@router.get("/reports/{scan_id}")
def get_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {
        **scan.to_dict(),
        "findings": [f.to_dict() for f in scan.findings],
    }
