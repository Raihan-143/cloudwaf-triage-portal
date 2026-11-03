from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from core.waf.middleware import CloudWAFMiddleware
from db.models import initialize_database
from utils.logger import PortalLogger

app = FastAPI(
    title="CloudWAF & Vulnerability Triage Portal",
    version="1.0.0",
    docs_url="/api/docs"
)

# 1. Initialize SQLite Database Tables
initialize_database()
PortalLogger.success("Database layer initialized and tables verified.")

# 2. Register WAF Inspection Middleware
app.add_middleware(CloudWAFMiddleware)
PortalLogger.info("CloudWAF Layer-7 active defense middleware armed.")

# 3. Mount Static Assets & Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# System Health Check endpoint
@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "waf_engine": "ACTIVE",
        "auditor_service": "READY"
    }


# Simulated application test endpoint (Protected by WAF)
@app.get("/api/v1/user/search")
async def simulated_user_search(q: str = ""):
    return {
        "message": "Benign search executed successfully.",
        "query": q,
        "results": []
    }