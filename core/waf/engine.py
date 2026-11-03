import urllib.parse
from typing import Optional, Tuple
from core.waf.rules import WAF_SIGNATURES


class WAFEngine:
    @staticmethod
    def normalize_and_decode(payload: str) -> str:
        """
        Recursively decodes URL-encoded and obfuscated payloads to prevent evasion.
        """
        current = payload
        for _ in range(3):  # Handles double or triple URL-encoding attempts
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        return current

    @classmethod
    def inspect_request(
        cls,
        path: str,
        query_params: str,
        user_agent: str,
        body: str = ""
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Inspects incoming HTTP telemetry against compiled threat vectors.
        Returns: (is_threat_detected, threat_type, offending_payload)
        """
        # 1. Inspect User-Agent for known malicious automated scanners
        if user_agent and WAF_SIGNATURES["Malicious Automated Scanner"].search(user_agent):
            return True, "Malicious Automated Scanner", user_agent

        # 2. Inspect query parameters, URI path, and body content
        targets_to_inspect = [path, query_params, body]

        for target in targets_to_inspect:
            if not target:
                continue

            normalized_target = cls.normalize_and_decode(target)

            for threat_type, pattern in WAF_SIGNATURES.items():
                if threat_type == "Malicious Automated Scanner":
                    continue

                match = pattern.search(normalized_target)
                if match:
                    # Capture snippet around offending payload
                    offending_snippet = match.group(0)
                    return True, threat_type, offending_snippet

        return False, None, None