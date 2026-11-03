import httpx
from typing import Dict, Any, List
from core.auditor.audit_rules import RECOMMENDED_HEADERS, SENSITIVE_PATHS


class VulnerabilityScanner:
    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    @classmethod
    async def audit_target(cls, target_url: str) -> Dict[str, Any]:
        """
        Executes an asynchronous non-intrusive security audit against the target URL.
        Returns a structured dictionary of findings, status, and aggregate score.
        """
        base_url = cls._normalize_url(target_url)
        findings: List[Dict[str, Any]] = []
        aggregate_score = 100

        headers_to_send = {
            "User-Agent": "CloudWAF-Triage-Auditor/1.0"
        }

        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
            # 1. Audit Security Headers
            try:
                response = await client.get(base_url, headers=headers_to_send)
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                for header, meta in RECOMMENDED_HEADERS.items():
                    if header.lower() not in resp_headers:
                        aggregate_score -= meta["weight"]
                        findings.append({
                            "category": "Missing Security Header",
                            "item": header,
                            "severity": "Medium" if meta["weight"] <= 10 else "High",
                            "impact": meta["description"],
                            "recommendation": f"Add '{header}: {meta['directive_hint']}'"
                        })
                    else:
                        findings.append({
                            "category": "Present Security Header",
                            "item": header,
                            "severity": "Info",
                            "impact": "Configured correctly",
                            "recommendation": "Pass"
                        })

            except Exception as err:
                return {
                    "target_url": base_url,
                    "status": "FAILED",
                    "error": f"Failed to connect to target: {str(err)}",
                    "security_score": 0,
                    "findings": []
                }

            # 2. Check for Exposed Sensitive Files (High-risk info leaks)
            for path in SENSITIVE_PATHS:
                test_url = f"{base_url}{path}"
                try:
                    path_resp = await client.get(test_url, headers=headers_to_send)
                    # If file returns 200 OK and is not an HTML error redirect
                    content_type = path_resp.headers.get("content-type", "").lower()
                    if path_resp.status_code == 200 and "text/html" not in content_type:
                        aggregate_score -= 25
                        findings.append({
                            "category": "Exposed Sensitive Asset",
                            "item": path,
                            "severity": "Critical",
                            "impact": "Confidential internal file or secret exposure.",
                            "recommendation": "Block public access via web server configuration."
                        })
                except Exception:
                    continue

        final_score = max(0, aggregate_score)

        return {
            "target_url": base_url,
            "status": "SUCCESS",
            "security_score": final_score,
            "findings": findings
        }