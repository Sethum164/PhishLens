
# PhishLens Domain Threat Analyzer

import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan",
    ".work", ".country", ".gq", ".tk"
}

BRAND_KEYWORDS = {
    "paypal", "google", "microsoft",
    "apple", "amazon", "facebook",
    "netflix", "instagram"
}

CHARACTER_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t"
})


def normalize_domain_name(name):
    return name.lower().translate(CHARACTER_MAP)


def validate_domain(domain):

    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        return False

    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    for label in labels:

        if not label or len(label) > 63:
            return False

        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
            label
        ):
            return False

    return True


def analyze_domain_threat(domain):

    if not isinstance(domain, str):
        domain = ""

    domain = domain.strip().lower().rstrip(".")

    findings = []
    risk_score = 0

    if not domain:
        return {
            "domain": "",
            "risk_score": 0,
            "risk_level": "Unknown",
            "findings": [],
            "status": "No domain provided"
        }

    # Extract hostname if a URL was provided
    if "://" in domain:

        try:
            parsed_url = urlparse(domain)

            if parsed_url.scheme.lower() not in ("http", "https"):
                raise ValueError

            if not parsed_url.hostname:
                raise ValueError

            if parsed_url.port is not None:
                if not (1 <= parsed_url.port <= 65535):
                    raise ValueError

            domain = parsed_url.hostname.lower().rstrip(".")

        except (ValueError, TypeError):
            return {
                "domain": domain,
                "risk_score": 0,
                "risk_level": "Unknown",
                "findings": [],
                "status": "Invalid domain or URL"
            }

    if not validate_domain(domain):
        return {
            "domain": domain,
            "risk_score": 0,
            "risk_level": "Unknown",
            "findings": [],
            "status": "Invalid domain"
        }

    findings = []
    risk_score = 0

    def add_finding(message, points):
        nonlocal risk_score

        if message not in findings:
            findings.append(message)
            risk_score += points

    parts = domain.split(".")

    # 1. Check Punycode
    if any(part.startswith("xn--") for part in parts):
        add_finding(
            "Domain contains Punycode characters",
            20
        )

    # 2. Check suspicious TLDs
    tld = "." + parts[-1]

    if tld in SUSPICIOUS_TLDS:
        add_finding(
            f"Uses a TLD requiring investigation: {tld}",
            15
        )

    # 3. Check main domain label
    registered_name = parts[-2]

    if len(registered_name) > 20:
        add_finding(
            "Domain name is unusually long",
            10
        )

    # 4. Check excessive subdomains
    if len(parts) > 4:
        add_finding(
            "Domain contains many subdomains",
            15
        )

    # 5. Check multiple hyphens
    if domain.count("-") >= 2:
        add_finding(
            "Domain contains multiple hyphens",
            10
        )

    # 6. Check possible brand impersonation
    domain_labels = parts[:-1]

    for label in domain_labels:

        normalized_label = normalize_domain_name(label)

        for brand in BRAND_KEYWORDS:

            if normalized_label == brand and label != brand:

                add_finding(
                    f"Possible lookalike domain using brand name: {brand}",
                    25
                )

                break

    # 7. Check numeric characters
    if re.search(r"\d", registered_name):
        add_finding(
            "Domain name contains numeric characters",
            5
        )

    risk_score = min(risk_score, 100)

    # Risk classification
    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
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


def analyze_domains_threat(domains):

    if not isinstance(domains, (list, tuple, set)):
        domains = []

    unique_domains = []
    seen = set()

    for domain in domains:

        if not isinstance(domain, str):
            continue

        normalized = domain.strip().lower().rstrip(".")

        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_domains.append(domain)

    results = [
        analyze_domain_threat(domain)
        for domain in unique_domains
    ]

    return {
        "total_domains_analyzed": len(results),
        "domain_results": results
    }
