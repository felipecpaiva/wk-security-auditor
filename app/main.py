"""Enterprise Security Guardrail Auditor — FastAPI Application."""

from pathlib import Path
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.db import init_db, get_db
from app.models import Scan
from app.api.scan import router as scan_router
from app.api.reports import router as reports_router

app = FastAPI(
    title="Enterprise Security Guardrail Auditor",
    description="Audit Terraform and CloudFormation configs against security baselines",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(scan_router)
app.include_router(reports_router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"message": "Enterprise Security Guardrail Auditor", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.scanned_at.desc()).all()
    total_scans = len(scans)
    if scans:
        latest = scans[0]
        avg_score = round(sum(s.risk_score for s in scans) / total_scans, 1)
        total_critical = sum(s.critical_count for s in scans)
        total_high = sum(s.high_count for s in scans)
        total_medium = sum(s.medium_count for s in scans)
        total_low = sum(s.low_count for s in scans)
    else:
        latest = None
        avg_score = 0
        total_critical = total_high = total_medium = total_low = 0

    scans_json = [s.to_dict() for s in scans]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_scans": total_scans,
        "latest": latest,
        "avg_score": avg_score,
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
        "scans": scans,
        "scans_json": scans_json,
    })
