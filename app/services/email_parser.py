
# PhishLens Secure Email Parser

from email import policy
from email.parser import BytesParser
from email.errors import MessageError

import re
import ipaddress

from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Import analysis modules
from app.services.header_analyzer import analyze_headers
from app.services.ioc_analyzer import analyze_iocs
from app.services.risk_scorer import calculate_risk_score
from app.services.attachment_analyzer import analyze_attachments


# Security limits
MAX_EMAIL_SIZE = 5 * 1024 * 1024
MAX_MIME_PARTS = 100
MAX_ATTACHMENTS = 25
MAX_BODY_SIZE = 1024 * 1024


def get_safe_content(part):
    """Safely extract text from an email MIME part."""

    try:
        content = part.get_content()

        if isinstance(content, str):
            return content

        if isinstance(content, bytes):
            charset = part.get_content_charset() or "utf-8"
            return content.decode(charset, errors="replace")

        return ""

    except (UnicodeError, LookupError, TypeError, ValueError):
        payload = part.get_payload(decode=True)

        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")

        return ""


# Parse uploaded email and extract information
def parse_email(email_data):

    # Validate input type
    if not isinstance(email_data, bytes):
        raise ValueError("Email data must be bytes.")

    # Validate empty email
    if not email_data:
        raise ValueError("The uploaded email is empty.")

    # Validate email size
    if len(email_data) > MAX_EMAIL_SIZE:
        raise ValueError("Email exceeds the 5 MB limit.")

    # Parse email safely
    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(email_data)

    except (MessageError, ValueError, TypeError) as error:
        raise ValueError("Unable to parse the email.") from error

    # Check for recognizable email headers
    known_headers = {
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID"
    }

    if not any(message.get(header) for header in known_headers):
        raise ValueError("Uploaded file does not contain valid email headers.")

    # Count MIME parts
    mime_parts = list(message.walk())

    if len(mime_parts) > MAX_MIME_PARTS:
        raise ValueError("Email contains too many MIME parts.")

    # Extract email headers
    email_details = {
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "message_id": message.get("Message-ID", ""),
        "received": message.get_all("Received", []),
        "authentication_results": message.get_all(
            "Authentication-Results", []
        )
    }

    # Extract plain-text email body
    body = message.get_body(preferencelist=("plain",))

    email_body = get_safe_content(body) if body else ""

    # Extract HTML email body
    html_part = message.get_body(preferencelist=("html",))

    html_body = get_safe_content(html_part) if html_part else ""

    # Validate combined body size
    if len(email_body.encode("utf-8")) + len(
        html_body.encode("utf-8")
    ) > MAX_BODY_SIZE:
        raise ValueError("Email body exceeds the 1 MB limit.")

    email_details["body"] = email_body
    email_details["html_body"] = html_body

    # Extract attachment information
    attachments = []

    for part in message.iter_attachments():

        if len(attachments) >= MAX_ATTACHMENTS:
            raise ValueError("Email contains too many attachments.")

        filename = part.get_filename()
        content_type = part.get_content_type()

        attachment_data = part.get_payload(decode=True)

        if not isinstance(attachment_data, bytes):
            attachment_data = b""

        file_size = len(attachment_data)

        attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size": file_size
        })

    email_details["attachments"] = attachments

    # Combine email bodies for IOC extraction
    email_content = email_body + " " + html_body

    # Extract URLs from HTML links
    soup = BeautifulSoup(html_body, "html.parser")

    html_urls = []

    for link in soup.find_all("a", href=True):

        url = link.get("href")

        if url and urlparse(url).scheme.lower() in ("http", "https"):
            html_urls.append(url)

    # Extract URLs using regular expressions
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email_content,
        re.IGNORECASE
    )

    # Add HTML links
    urls.extend(html_urls)

    # Remove trailing punctuation
    urls = [
        url.rstrip(".,;:!?)]}")
        for url in urls
    ]

    # Remove empty URLs and duplicates
    urls = list(dict.fromkeys(url for url in urls if url))

    email_details["urls"] = urls

    # Extract domains from URLs
    domains = []

    for url in urls:

        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if domain:

            try:
                ipaddress.ip_address(domain)

            except ValueError:
                domains.append(domain)

    domains = list(dict.fromkeys(domains))

    email_details["domains"] = domains

    # Extract IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    found_ips = re.findall(
        ip_pattern,
        email_content + " " + " ".join(urls)
    )

    # Validate IP addresses
    ip_addresses = []

    for ip in found_ips:

        try:
            ipaddress.IPv4Address(ip)
            ip_addresses.append(ip)

        except ValueError:
            continue

    ip_addresses = list(dict.fromkeys(ip_addresses))

    email_details["ip_addresses"] = ip_addresses

    # Run Header Analyzer
    header_analysis = analyze_headers(email_details)
    email_details["header_analysis"] = header_analysis

    # Run IOC Analyzer
    ioc_analysis = analyze_iocs(email_details)
    email_details["ioc_analysis"] = ioc_analysis

    # Run Attachment Analyzer
    attachment_analysis = analyze_attachments(email_details)
    email_details["attachment_analysis"] = attachment_analysis

    # Run Risk Scoring Engine
    risk_analysis = calculate_risk_score(email_details)
    email_details["risk_analysis"] = risk_analysis

    return email_details
