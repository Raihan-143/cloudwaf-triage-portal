from typing import Dict, List

# Standard security headers and their remediation impact weights
RECOMMENDED_HEADERS: Dict[str, Dict[str, any]] = {
    "Content-Security-Policy": {
        "weight": 20,
        "description": "Defends against Cross-Site Scripting (XSS) and data injection.",
        "directive_hint": "default-src 'self'"
    },
    "Strict-Transport-Security": {
        "weight": 20,
        "description": "Enforces HTTPS communication and mitigates SSL-stripping.",
        "directive_hint": "max-age=31536000; includeSubDomains"
    },
    "X-Frame-Options": {
        "weight": 15,
        "description": "Mitigates Clickjacking attacks by restricting iframe embedding.",
        "directive_hint": "DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "description": "Prevents MIME-type sniffing by clients.",
        "directive_hint": "nosniff"
    },
    "Referrer-Policy": {
        "weight": 10,
        "description": "Controls how much referrer information is leaked in requests.",
        "directive_hint": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "weight": 5,
        "description": "Restricts browser feature usage like camera, microphone, and geolocation.",
        "directive_hint": "geolocation=()"
    }
}

# High-risk sensitive files and paths that should never be publicly accessible
SENSITIVE_PATHS: List[str] = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/config.json",
    "/backup.sql",
    "/database.sqlite"
]