from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from sqlalchemy import func

from . import models, schemas, database, alert_processor, suricata_reader, config

# -------------------------------------------------
# Logging configuration
# -------------------------------------------------
import logging
logging.basicConfig(
    level=getattr(logging, config.Settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)

# -------------------------------------------------
# FastAPI app & CORS
# -------------------------------------------------
app = FastAPI(
    title="NIDS Backend API",
    description="FastAPI service that stores Suricata alerts and serves dashboard data.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production restrict origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# Database init (create tables if missing) & seed sample data
# -------------------------------------------------
models.Base.metadata.create_all(bind=database.engine)

try:
    with database.SessionLocal() as init_db:
        if init_db.query(models.Alert).count() == 0:
            alert_processor.ingest_eve_json(init_db)
except Exception as e:
    log.warning(f"Initial alert population note: {e}")

# -------------------------------------------------
# Health check
# -------------------------------------------------
@app.get("/api/health", tags=["Health"])
def health():
    return {"status": "ok"}

# -------------------------------------------------
# Alert endpoints
# -------------------------------------------------
@app.get("/api/alerts", response_model=list[schemas.AlertOut], tags=["Alerts"])
def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(database.get_db),
):
    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if status:
        query = query.filter(models.Alert.status == status)
    return query.order_by(models.Alert.timestamp.desc()).all()

@app.get("/api/alerts/{alert_id}", response_model=schemas.AlertOut, tags=["Alerts"])
def get_alert(alert_id: int, db: Session = Depends(database.get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.patch("/api/alerts/{alert_id}", response_model=schemas.AlertOut, tags=["Alerts"])
def update_alert(
    alert_id: int,
    payload: schemas.AlertUpdate = Body(...),
    db: Session = Depends(database.get_db),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if payload.status:
        alert.status = payload.status
    if payload.description is not None:
        alert.description = payload.description
    db.commit()
    db.refresh(alert)
    return alert

# -------------------------------------------------
# Stats endpoint (for dashboard)
# -------------------------------------------------
@app.get("/api/stats", tags=["Stats"])
def get_stats(db: Session = Depends(database.get_db)):
    total = db.query(models.Alert).count()
    severity_counts = (
        db.query(models.Alert.severity, func.count(models.Alert.id))
        .group_by(models.Alert.severity)
        .all()
    )
    protocol_counts = (
        db.query(models.Alert.protocol, func.count(models.Alert.id))
        .group_by(models.Alert.protocol)
        .all()
    )
    now = datetime.utcnow()
    last_24h = (
        db.query(models.Alert)
        .filter(models.Alert.timestamp >= now - timedelta(hours=24))
        .count()
    )
    last_7d = (
        db.query(models.Alert)
        .filter(models.Alert.timestamp >= now - timedelta(days=7))
        .count()
    )
    return {
        "total": total,
        "by_severity": dict(severity_counts),
        "by_protocol": dict(protocol_counts),
        "last_24h": last_24h,
        "last_7d": last_7d,
    }

# -------------------------------------------------
# PCAP analysis endpoint (offline testing)
# -------------------------------------------------
@app.post("/api/pcap/analyze", tags=["PCAP"])
def analyze_pcap(
    pcap_path: str = Body(..., embed=True, description="Absolute path to PCAP."),
    db: Session = Depends(database.get_db),
):
    eve_path = config.Settings.SURICATA_EVE_PATH
    success = suricata_reader.run_suricata(
        pcap_path=pcap_path,
        config_path=str(Path(__file__).parent.parent / "suricata" / "suricata.yaml"),
        eve_path=eve_path,
    )
    if not success:
        raise HTTPException(status_code=500, detail="Suricata execution failed")
    added = alert_processor.ingest_eve_json(db)
    return {"added_alerts": added, "eve_log": eve_path}

# -------------------------------------------------
# Alert Simulation Endpoint (for testing live alerts)
# -------------------------------------------------
@app.post("/api/simulate/alert", response_model=schemas.AlertOut, tags=["Simulation"])
def simulate_alert(
    payload: schemas.AlertCreate,
    db: Session = Depends(database.get_db),
):
    alert = models.Alert(
        timestamp=payload.timestamp or datetime.utcnow(),
        source_ip=payload.source_ip or "192.168.1.199",
        source_port=payload.source_port or 55432,
        dest_ip=payload.dest_ip or "10.0.0.1",
        dest_port=payload.dest_port or 80,
        protocol=(payload.protocol or "TCP").upper(),
        signature=payload.signature or "ET TEST Simulated Intrusion Event",
        category=payload.category or "Security Test",
        severity=payload.severity or "High",
        status="open",
        description=payload.description or "Manually injected threat detection for validation.",
        raw_data='{"simulated": true}',
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

# -------------------------------------------------
# Serve Frontend Static Files & SPA
# -------------------------------------------------
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", tags=["Frontend"])
    def serve_frontend_root():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"message": "Frontend index.html not found"}
