from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from core.waf.middleware import CloudWAFMiddleware
from core.auditor.scanner import VulnerabilityScanner
from db.models import initialize_database, get_db_connection
from utils.logger import PortalLogger

app = FastAPI(
    title="CloudWAF & Vulnerability Triage Portal",
    version="1.0.0",
    docs_url="/api/docs"
)

# Initialize Database
initialize_database()

# Register WAF Middleware
app.add_middleware(CloudWAFMiddleware)

# Mount Assets & Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class TargetScanRequest(BaseModel):
    target_url: str


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the interactive 3D Cyber Command Dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/v1/metrics")
async def get_security_metrics():
    """Returns aggregated threat metrics and recent incidents for the HUD."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total_blocked FROM security_events WHERE status = 'BLOCKED'")
    total_blocked = cursor.fetchone()["total_blocked"]

    cursor.execute("""
        SELECT threat_type, COUNT(*) as count 
        FROM security_events 
        GROUP BY threat_type
    """)
    threat_breakdown = {row["threat_type"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("""
        SELECT timestamp, client_ip, threat_type, payload_sample, endpoint 
        FROM security_events 
        ORDER BY id DESC LIMIT 8
    """)
    recent_events = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "total_blocked": total_blocked,
        "threat_breakdown": threat_breakdown,
        "recent_events": recent_events
    }


@app.post("/api/v1/audit")
async def run_vulnerability_audit(payload: TargetScanRequest):
    """Triggers asynchronous non-intrusive target security scan."""
    result = await VulnerabilityScanner.audit_target(payload.target_url)
    return result