
# PhishLens Header Analyzer

import re
import ipaddress

from email.utils import parseaddr


# Extract domain from an email address
def extract_email_domain(email_address):

    if not email_address or not isinstance(email_address, str):
        return None

    try:
        parsed_address = parseaddr(email_address)[1]

        if "@" not in parsed_address:
            return None

        domain = parsed_address.rsplit("@", 1)[1].strip().lower()

        if not domain or domain.startswith("[") or domain.endswith("]"):
            return None

        return domain

    except (ValueError, TypeError):
        return None


# Analyze From and Reply-To headers
def analyze_reply_to(email_details):

    from_domain = extract_email_domain(
        email_details.get("from", "")
    )

    reply_to_domain = extract_email_domain(
        email_details.get("reply_to", "")
    )

    mismatch = bool(
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    )

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "mismatch": mismatch
    }


# Analyze From and Return-Path headers
def analyze_return_path(email_details):

    from_domain = extract_email_domain(
        email_details.get("from", "")
    )

    return_path_domain = extract_email_domain(
        email_details.get("return_path", "")
    )

    mismatch = bool(
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    )

    return {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "mismatch": mismatch
    }


# Analyze SPF, DKIM and DMARC results
def analyze_authentication(email_details):

    authentication_results = email_details.get(
        "authentication_results", []
    )

    if isinstance(authentication_results, str):
        authentication_results = [authentication_results]

    auth_text = " ".join(
        str(item) for item in authentication_results
    ).lower()

    def extract_result(protocol):

        pattern = (
            rf"\b{protocol}\s*=\s*"
            rf"(pass|fail|softfail|neutral|none|temperror|permerror)"
            rf"\b"
        )

        match = re.search(pattern, auth_text)

        return match.group(1) if match else "unknown"

    return {
        "spf": extract_result("spf"),
        "dkim": extract_result("dkim"),
        "dmarc": extract_result("dmarc"),
        "source": "Unverified uploaded Authentication-Results header"
    }


# Analyze Received email headers
def analyze_received_headers(email_details):

    received_headers = email_details.get("received", [])

    if isinstance(received_headers, str):
        received_headers = [received_headers]

    ip_addresses = []

    # Extract IPv4 and IPv6 addresses
    for header in received_headers:

        if not isinstance(header, str):
            continue

        found_ips = re.findall(
            r"(?<![a-fA-F0-9:.])"
            r"(?:[a-fA-F0-9:.]+)"
            r"(?![a-fA-F0-9:.])",
            header
        )

        for ip in found_ips:

            try:
                validated_ip = ipaddress.ip_address(ip)
                ip_addresses.append(str(validated_ip))

            except ValueError:
                continue

    ip_addresses = list(dict.fromkeys(ip_addresses))

    return {
        "received_headers": received_headers,
        "ip_addresses": ip_addresses,
        "header_count": len(received_headers)
    }


# Run all email header analysis functions
def analyze_headers(email_details):

    reply_to_analysis = analyze_reply_to(email_details)

    return_path_analysis = analyze_return_path(email_details)

    authentication_analysis = analyze_authentication(email_details)

    received_analysis = analyze_received_headers(email_details)

    return {
        "reply_to_analysis": reply_to_analysis,
        "return_path_analysis": return_path_analysis,
        "authentication_analysis": authentication_analysis,
        "received_analysis": received_analysis
    }
