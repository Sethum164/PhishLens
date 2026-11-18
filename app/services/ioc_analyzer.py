
# PhishLens IOC Analyzer

import ipaddress
import re

from urllib.parse import urlparse

from app.services.dns_analyzer import analyze_dns
from app.services.threat_intel_analyzer import analyze_url_threat
from app.services.domain_threat_analyzer import analyze_domains_threat


# Validate and normalize a URL
def normalize_url(url):

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

        # Validate hostname / IP address
        hostname = parsed.hostname

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if (
                len(hostname) > 253
                or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
                    hostname
                )
            ):
                return None

        # Validate port if present
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return None

        return url

    except (ValueError, TypeError):
        return None


# Classify IP addresses
def classify_ip_address(ip_object):

    if ip_object.is_loopback:
        return "Loopback"

    if ip_object.is_private:
        return "Private"

    if ip_object.is_link_local:
        return "Link-local"

    if ip_object.is_global:
        return "Public"

    return "Reserved / Special"


# Analyze URLs
def analyze_urls(email_details):

    urls = email_details.get("urls", [])
    analyzed_urls = []
    unique_urls = []

    if not isinstance(urls, list):
        urls = []

    for url in urls:

        normalized = normalize_url(url)

        if normalized and normalized not in unique_urls:
            unique_urls.append(normalized)

    for url in unique_urls:

        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        scheme = parsed_url.scheme.lower()

        protocol = scheme.upper()

        is_ip_address = False

        if domain:
            try:
                ipaddress.ip_address(domain)
                is_ip_address = True
            except ValueError:
                pass

        warnings = []

        if scheme == "http":
            warnings.append("Uses HTTP instead of HTTPS")

        if is_ip_address:
            warnings.append(
                "Uses an IP address instead of a domain name"
            )

        if parsed_url.username or parsed_url.password:
            warnings.append(
                "Contains credentials in the URL"
            )

        if "@" in url:
            warnings.append(
                "Contains an @ symbol in the URL"
            )

        analyzed_urls.append({
            "url": url,
            "domain": domain,
            "protocol": protocol,
            "is_ip_address": is_ip_address,
            "warnings": warnings
        })

    return {
        "total_urls": len(analyzed_urls),
        "urls": analyzed_urls
    }


# Analyze domains
def analyze_domains(email_details):

    domains = email_details.get("domains", [])

    if not isinstance(domains, list):
        domains = []

    unique_domains = list(dict.fromkeys(
        domain.strip().lower()
        for domain in domains
        if isinstance(domain, str) and domain.strip()
    ))

    analyzed_domains = []

    for domain in unique_domains:

        is_ip_address = False

        try:
            ipaddress.ip_address(domain)
            is_ip_address = True
        except ValueError:
            pass

        if not is_ip_address:

            if (
                len(domain) > 253
                or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                    domain
                )
            ):
                continue

        analyzed_domains.append({
            "domain": domain,
            "is_ip_address": is_ip_address
        })

    return {
        "total_domains": len(analyzed_domains),
        "domains": analyzed_domains
    }


# Analyze IP addresses
def analyze_ip_addresses(email_details):

    ip_addresses = email_details.get("ip_addresses", [])

    if not isinstance(ip_addresses, list):
        ip_addresses = []

    unique_ips = list(dict.fromkeys(
        ip.strip()
        for ip in ip_addresses
        if isinstance(ip, str) and ip.strip()
    ))

    analyzed_ips = []

    for ip in unique_ips:

        try:
            ip_object = ipaddress.ip_address(ip)

            analyzed_ips.append({
                "ip_address": ip,
                "version": ip_object.version,
                "type": classify_ip_address(ip_object)
            })

        except ValueError:
            continue

    return {
        "total_ips": len(analyzed_ips),
        "ip_addresses": analyzed_ips
    }


# Analyze domain DNS information
def analyze_domain_dns(email_details):

    domains = email_details.get("domains", [])

    if not isinstance(domains, list):
        domains = []

    unique_domains = list(dict.fromkeys(
        domain.strip().lower()
        for domain in domains
        if isinstance(domain, str) and domain.strip()
    ))

    dns_results = []

    for domain in unique_domains:

        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        try:
            result = analyze_dns(domain)
            dns_results.append(result)

        except Exception as error:
            dns_results.append({
                "domain": domain,
                "error": "DNS lookup failed"
            })

    return {
        "total_domains_analyzed": len(dns_results),
        "dns_results": dns_results
    }


# Analyze URL threat intelligence
def analyze_url_threat_intelligence(email_details):

    urls = email_details.get("urls", [])

    if not isinstance(urls, list):
        urls = []

    analyzed_urls = []

    for url in urls:

        normalized = normalize_url(url)

        if not normalized:
            continue

        try:
            result = analyze_url_threat(normalized)
            analyzed_urls.append(result)

        except Exception:
            analyzed_urls.append({
                "url": normalized,
                "error": "URL threat intelligence lookup failed"
            })

    return {
        "total_urls_analyzed": len(analyzed_urls),
        "url_results": analyzed_urls
    }


# Analyze domain threat intelligence
def analyze_domain_threat_intelligence(email_details):

    domains = email_details.get("domains", [])

    if not isinstance(domains, list):
        domains = []

    valid_domains = []

    for domain in domains:

        if not isinstance(domain, str):
            continue

        domain = domain.strip().lower()

        if not domain:
            continue

        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        if (
            len(domain) <= 253
            and re.fullmatch(
                r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                domain
            )
        ):
            valid_domains.append(domain)

    valid_domains = list(dict.fromkeys(valid_domains))

    try:
        return analyze_domains_threat(valid_domains)

    except Exception:
        return {
            "error": "Domain threat intelligence lookup failed",
            "total_domains_analyzed": 0
        }


# Run all IOC analysis functions
def analyze_iocs(email_details):

    url_analysis = analyze_urls(email_details)

    domain_analysis = analyze_domains(email_details)

    ip_analysis = analyze_ip_addresses(email_details)

    dns_analysis = analyze_domain_dns(email_details)

    threat_intelligence_analysis = (
        analyze_url_threat_intelligence(email_details)
    )

    domain_threat_analysis = (
        analyze_domain_threat_intelligence(email_details)
    )

    return {
        "url_analysis": url_analysis,
        "domain_analysis": domain_analysis,
        "ip_analysis": ip_analysis,
        "dns_analysis": dns_analysis,
        "threat_intelligence_analysis": threat_intelligence_analysis,
        "domain_threat_analysis": domain_threat_analysis
    }
