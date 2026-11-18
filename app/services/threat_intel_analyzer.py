
# PhishLens Local Threat Intelligence Analyzer

from urllib.parse import urlparse, unquote
import ipaddress
import re


# Common URL shortener services
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly"
}


# Suspicious file extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js",
    ".vbs", ".ps1", ".jar", ".msi", ".hta",
    ".com", ".pif", ".dll", ".iso", ".zip"
}


# Common suspicious URL keywords
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "update",
    "secure",
    "signin",
    "banking",
    "wallet"
}


# Validate and normalize URL
def validate_url(url):

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url or len(url) > 2048:
        return None

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        if not parsed.hostname:
            return None

        # Validate port if present
        if parsed.port is not None:
            if not (1 <= parsed.port <= 65535):
                return None

        return parsed

    except (ValueError, TypeError):
        return None


# Analyze URL threat indicators
def analyze_url_threat(url):

    parsed_url = validate_url(url)

    # Return safe error structure for invalid URLs
    if parsed_url is None:
        return {
            "url": str(url)[:2048],
            "domain": "",
            "risk_score": 0,
            "risk_level": "Unknown",
            "findings": [],
            "status": "Invalid URL - unable to analyze"
        }

    domain = (parsed_url.hostname or "").lower()

    findings = []
    risk_score = 0

    def add_finding(message, points):
        nonlocal risk_score

        if message not in findings:
            findings.append(message)
            risk_score += points

    # 1. Check whether URL uses an IP address
    try:
        ipaddress.ip_address(domain)

        add_finding(
            "URL uses an IP address instead of a domain",
            25
        )

    except ValueError:
        pass

    # 2. Check URL shorteners
    if domain in URL_SHORTENERS:
        add_finding(
            "URL uses a known URL shortening service",
            20
        )

    # 3. Check suspicious keywords
    decoded_url = unquote(url).lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in decoded_url:
            add_finding(
                f"URL contains suspicious keyword: {keyword}",
                5
            )

    # 4. Check excessive subdomains
    domain_parts = domain.split(".")

    if len(domain_parts) > 4:
        add_finding(
            "Domain contains an unusually high number of subdomains",
            15
        )

    # 5. Check username or password in URL
    if parsed_url.username or parsed_url.password:
        add_finding(
            "URL contains embedded username or password",
            20
        )

    # 6. Check dangerous file extensions
    path = unquote(parsed_url.path).lower()

    if any(
        path.endswith(extension)
        for extension in DANGEROUS_EXTENSIONS
    ):
        add_finding(
            "URL points to a potentially dangerous file",
            25
        )

    # 7. Check suspicious URL encoding
    if re.search(r"%[0-9a-fA-F]{2}", url):
        add_finding(
            "URL contains encoded characters",
            5
        )

    # 8. Check HTTP protocol
    if parsed_url.scheme.lower() == "http":
        add_finding(
            "URL does not use HTTPS encryption",
            10
        )

    # Keep score between 0 and 100
    risk_score = min(risk_score, 100)

    # Risk classification
    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "status": (
            "Suspicious indicators detected"
            if findings
            else "No suspicious indicators detected"
        )
    }
