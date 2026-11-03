"""
core/waf/middleware.py
Starlette/FastAPI middleware for real-time payload inspection, blocking, and audit logging.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from core.waf.engine import WAFEngine
from db.models import get_db_connection
from utils.logger import PortalLogger


class CloudWAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path or ""

        # UI Dashboard, Static Files, and Internal APIs bypass direct blocking
        if path.startswith("/static") or path in ["/", "/favicon.ico"] or path.startswith("/api/v1/metrics") or path.startswith("/api/v1/audit"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        query_string = request.url.query or ""
        user_agent = request.headers.get("user-agent", "")

        # Inspect request via WAF engine
        is_threat, threat_type, offending_payload = WAFEngine.inspect_request(
            path=path,
            query_params=query_string,
            user_agent=user_agent,
            body=""
        )

        if is_threat:
            PortalLogger.alert(
                f"[BLOCKED] IP: {client_ip} | Threat: {threat_type} | Target: {path} | Payload: {offending_payload}"
            )

            # Persist security event to SQLite
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_events (client_ip, threat_type, payload_sample, endpoint, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (client_ip, threat_type, offending_payload, path, "BLOCKED"))
                conn.commit()
                conn.close()
            except Exception as e:
                PortalLogger.warning(f"Database logging failure: {e}")

            return JSONResponse(
                status_code=403,
                content={
                    "status": "ACCESS_DENIED",
                    "code": 403,
                    "incident_response": "Request blocked by CloudWAF Active Defense Layer.",
                    "threat_classification": threat_type,
                    "offending_signature": offending_payload
                }
            )

        return await call_next(request)