from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from core.waf.engine import WAFEngine
from db.models import get_db_connection
from utils.logger import PortalLogger


class CloudWAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Static files এবং Dashboard UI inspection bypass (performance optimization)
        path = request.url.path
        if path.startswith("/static") or path in ["/", "/favicon.ico"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        query_string = request.url.query
        user_agent = request.headers.get("user-agent", "")

        # Read body for POST/PUT inspection without consuming the stream permanently
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="ignore")

        # Inspect request via WAF engine
        is_threat, threat_type, offending_payload = WAFEngine.inspect_request(
            path=path,
            query_params=query_string,
            user_agent=user_agent,
            body=body_text
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

            # Return immediate 403 Forbidden Response
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

        # Allow benign request to proceed
        response = await call_next(request)
        return response