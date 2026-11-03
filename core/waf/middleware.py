from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from core.waf.engine import WAFEngine
from db.models import get_db_connection
from utils.logger import PortalLogger


class CloudWAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path or ""
        client_ip = request.client.host if request.client else "127.0.0.1"

        # 1. IP Blacklist Enforcement (Applies to all protected endpoints)
        if not (path.startswith("/static") or path in ["/", "/favicon.ico"] or path.startswith("/api/v1/defense")):
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM ip_blacklist WHERE ip_address = ?", (client_ip,))
            is_blacklisted = cursor.fetchone()
            conn.close()

            if is_blacklisted:
                PortalLogger.alert(f"[DROPPED] Connection rejected for blacklisted IP: {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "IP_QUARANTINED",
                        "code": 403,
                        "incident_response": "Access revoked by SOC Administrator. Client IP is blacklisted."
                    }
                )

        # UI Dashboard, Static Files, and Internal APIs bypass signature inspection
        if path.startswith("/static") or path in ["/", "/favicon.ico"] or path.startswith("/api/v1/"):
            return await call_next(request)

        query_string = request.url.query or ""
        user_agent = request.headers.get("user-agent", "")

        # 2. Inspect request via WAF engine
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

        response = await call_next(request)

        # 3. Virtual Patching Header Injection (Runtime hardening)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM waf_config WHERE key = 'virtual_patch_headers'")
        patch_row = cursor.fetchone()
        conn.close()

        if patch_row and patch_row["value"] == 1:
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=()"

        return response