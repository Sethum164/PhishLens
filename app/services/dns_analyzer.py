
# PhishLens DNS Analyzer

import re
import ipaddress
import dns.resolver
import dns.exception


# DNS security limits
DNS_TIMEOUT = 3
DNS_LIFETIME = 5
DNS_RETRIES = 1
MAX_RECORDS = 20


# Validate domain before DNS lookup
def validate_domain(domain):

    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    if not domain or len(domain) > 253:
        return False

    # IP addresses are not domain names
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    # Validate domain format
    pattern = (
        r"(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )

    return bool(re.fullmatch(pattern, domain))


# Analyze DNS records for a domain
def analyze_dns(domain):

    domain = domain.strip().lower() if isinstance(domain, str) else ""

    dns_results = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "errors": []
    }

    # Validate domain
    if not validate_domain(domain):
        dns_results["errors"].append(
            "Invalid domain name"
        )
        return dns_results

    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    resolver.retry_servfail = False

    # DNS record types
    record_types = {
        "A": "a_records",
        "AAAA": "aaaa_records",
        "MX": "mx_records",
        "NS": "ns_records"
    }

    # Query each DNS record type
    for record_type, result_key in record_types.items():

        try:

            answers = resolver.resolve(
                domain,
                record_type,
                lifetime=DNS_LIFETIME,
                search=False
            )

            for answer in answers:

                if len(dns_results[result_key]) >= MAX_RECORDS:
                    break

                dns_results[result_key].append(str(answer))

        except dns.resolver.NoAnswer:
            continue

        except dns.resolver.NXDOMAIN:
            dns_results["errors"].append(
                "Domain does not exist"
            )
            break

        except dns.resolver.Timeout:
            dns_results["errors"].append(
                f"DNS query timeout for {record_type} record"
            )

        except dns.resolver.NoNameservers:
            dns_results["errors"].append(
                f"No available nameservers for {record_type} record"
            )

        except dns.exception.DNSException as error:
            dns_results["errors"].append(
                f"{record_type} lookup failed: {type(error).__name__}"
            )

        except Exception:
            dns_results["errors"].append(
                f"{record_type} lookup failed"
            )

    return dns_results
