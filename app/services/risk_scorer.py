
# PhishLens Risk Scoring Engine

# Risk score configuration
RISK_WEIGHTS = {
    "reply_to_mismatch": 20,
    "return_path_mismatch": 15,
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 15,
    "http_url": 10,
    "ip_based_url": 15,
    "suspicious_attachment": 20
}


def calculate_email_risk_level(score):

    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


def safe_dict(value):
    return value if isinstance(value, dict) else {}


def safe_list(value):
    return value if isinstance(value, (list, tuple)) else []


def safe_points(value):

    if isinstance(value, bool):
        return 0

    if not isinstance(value, (int, float)):
        return 0

    if value < 0:
        return 0

    return min(int(value), 100)


def calculate_risk_score(email_details):

    email_details = safe_dict(email_details)

    header_analysis = safe_dict(
        email_details.get("header_analysis")
    )

    ioc_analysis = safe_dict(
        email_details.get("ioc_analysis")
    )

    attachment_analysis = safe_dict(
        email_details.get("attachment_analysis")
    )

    risk_score = 0
    risk_factors = []
    seen_factors = set()

    def add_factor(factor, points, **details):

        nonlocal risk_score

        if factor in seen_factors:
            return

        seen_factors.add(factor)

        points = safe_points(points)

        if points <= 0:
            return

        risk_score += points

        risk_factors.append({
            "factor": factor,
            "points": points,
            **details
        })

    # --------------------------------------------------
    # 1. EMAIL HEADER ANALYSIS
    # --------------------------------------------------

    reply_to = safe_dict(
        header_analysis.get("reply_to_analysis")
    )

    return_path = safe_dict(
        header_analysis.get("return_path_analysis")
    )

    authentication = safe_dict(
        header_analysis.get("authentication_analysis")
    )

    if reply_to.get("mismatch") is True:

        add_factor(
            "From and Reply-To domain mismatch",
            RISK_WEIGHTS["reply_to_mismatch"]
        )

    if return_path.get("mismatch") is True:

        add_factor(
            "From and Return-Path domain mismatch",
            RISK_WEIGHTS["return_path_mismatch"]
        )

    for auth_type in ("spf", "dkim", "dmarc"):

        if authentication.get(auth_type) == "fail":

            points = RISK_WEIGHTS[f"{auth_type}_fail"]

            add_factor(
                f"{auth_type.upper()} authentication failed",
                points
            )

    # --------------------------------------------------
    # 2. URL ANALYSIS
    # --------------------------------------------------

    url_analysis = safe_dict(
        ioc_analysis.get("url_analysis")
    )

    analyzed_urls = safe_list(
        url_analysis.get("urls")
    )

    seen_urls = set()

    for url_info in analyzed_urls:

        url_info = safe_dict(url_info)

        url = url_info.get("url")

        if not isinstance(url, str) or not url:
            continue

        url_key = url.strip().lower()

        if url_key in seen_urls:
            continue

        seen_urls.add(url_key)

        warnings = safe_list(
            url_info.get("warnings")
        )

        if "Uses HTTP instead of HTTPS" in warnings:

            add_factor(
                f"Insecure HTTP URL: {url}",
                RISK_WEIGHTS["http_url"],
                url=url
            )

        if "Uses an IP address instead of a domain name" in warnings:

            add_factor(
                f"IP-based URL: {url}",
                RISK_WEIGHTS["ip_based_url"],
                url=url
            )

    # --------------------------------------------------
    # 3. DOMAIN THREAT ANALYSIS
    # --------------------------------------------------

    domain_threat_analysis = safe_dict(
        ioc_analysis.get("domain_threat_analysis")
    )

    domain_results = safe_list(
        domain_threat_analysis.get("domain_results")
    )

    seen_domains = set()

    for domain_info in domain_results:

        domain_info = safe_dict(domain_info)

        domain = domain_info.get("domain", "")

        if not isinstance(domain, str):
            continue

        domain = domain.strip().lower()

        if not domain or domain in seen_domains:
            continue

        seen_domains.add(domain)

        points = safe_points(
            domain_info.get("risk_score")
        )

        findings = safe_list(
            domain_info.get("findings")
        )

        if points > 0:

            add_factor(
                f"Suspicious domain characteristics: {domain}",
                points,
                domain=domain,
                findings=findings
            )

    # --------------------------------------------------
    # 4. URL THREAT INTELLIGENCE
    # --------------------------------------------------

    threat_intelligence = safe_dict(
        ioc_analysis.get("threat_intelligence_analysis")
    )

    url_results = safe_list(
        threat_intelligence.get("url_results")
    )

    seen_threat_urls = set()

    for url_info in url_results:

        url_info = safe_dict(url_info)

        url = url_info.get("url", "")

        if not isinstance(url, str):
            continue

        url = url.strip()

        if not url or url in seen_threat_urls:
            continue

        seen_threat_urls.add(url)

        points = safe_points(
            url_info.get("risk_score")
        )

        findings = safe_list(
            url_info.get("findings")
        )

        if points > 0:

            add_factor(
                f"Suspicious URL characteristics: {url}",
                points,
                url=url,
                findings=findings
            )

    # --------------------------------------------------
    # 5. ATTACHMENT ANALYSIS
    # --------------------------------------------------

    analyzed_attachments = safe_list(
        attachment_analysis.get("attachments")
    )

    seen_attachments = set()

    for attachment in analyzed_attachments:

        attachment = safe_dict(attachment)

        if attachment.get("suspicious") is not True:
            continue

        filename = attachment.get("filename", "")

        if not isinstance(filename, str):
            filename = ""

        attachment_key = filename.strip().lower()

        if attachment_key in seen_attachments:
            continue

        seen_attachments.add(attachment_key)

        add_factor(
            f"Suspicious attachment: {filename}",
            RISK_WEIGHTS["suspicious_attachment"],
            filename=filename
        )

    # --------------------------------------------------
    # 6. FINAL RISK SCORE
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    risk_level = calculate_email_risk_level(
        risk_score
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors
    }
