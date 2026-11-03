import re
from typing import Dict, Pattern

WAF_SIGNATURES: Dict[str, Pattern] = {
    "SQL Injection (SQLi)": re.compile(
        r"(union\s+all\s+select|union\s+select|select\s+.*\s+from|"
        r"information_schema|waitfor\s+delay|sleep\(\d+\)|"
        r"benchmark\(\d+,|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|"
        r"(['\"])\s*or\s+\1|--\s*$|/\*.*?\*/|;\s*drop\s+table)",
        re.IGNORECASE,
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<script\b[^>]*>.*?</script>|<.*?javascript:|<.*?onload\s*=|"
        r"<.*?onerror\s*=|document\.cookie|window\.location|"
        r"eval\(.*?\)|alert\(.*?\)|prompt\(.*?\)|<iframe\b[^>]*>)",
        re.IGNORECASE,
    ),
    "Directory Traversal / LFI": re.compile(
        r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|"
        r"c:\\boot\.ini|/proc/self/environ|win\.ini|"
        r"\.\.%2f|\.\.%5c)",
        re.IGNORECASE,
    ),
    "Malicious Automated Scanner": re.compile(
        r"(sqlmap|nikto|gobuster|dirbuster|wpscan|masscan|"
        r"nmap|acunetix|havij|burpsuite)",
        re.IGNORECASE,
    ),
}