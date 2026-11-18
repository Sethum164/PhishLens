
# PhishLens Attachment Analyzer

import os


# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".js",
    ".vbs", ".ps1", ".scr", ".hta", ".jar",
    ".msi", ".docm", ".xlsm", ".zip", ".rar",
    ".iso", ".com", ".pif", ".reg", ".wsf",
    ".lnk", ".cpl", ".hta"
}


# Expected MIME types for selected extensions
EXPECTED_MIME_TYPES = {
    ".exe": {"application/x-msdownload", "application/octet-stream"},
    ".dll": {"application/x-msdownload", "application/octet-stream"},
    ".pdf": {"application/pdf"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".txt": {"text/plain"},
    ".html": {"text/html"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    },
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }
}


def analyze_attachments(email_details):

    if not isinstance(email_details, dict):
        email_details = {}

    attachments = email_details.get("attachments", [])

    if not isinstance(attachments, (list, tuple)):
        attachments = []

    analyzed_attachments = []

    for attachment in attachments:

        # Ignore malformed attachment entries
        if not isinstance(attachment, dict):
            continue

        filename = attachment.get("filename") or ""

        if not isinstance(filename, str):
            filename = ""

        filename = filename.strip()
        filename_lower = filename.lower()

        content_type = attachment.get("content_type")

        if not isinstance(content_type, str):
            content_type = ""

        content_type = content_type.lower().split(";")[0].strip()

        # Validate attachment size
        size = attachment.get("size", 0)

        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            size = 0

        findings = []

        # Get file extension
        extension = os.path.splitext(filename_lower)[1]

        # 1. Check suspicious extension
        if extension in SUSPICIOUS_EXTENSIONS:
            findings.append(
                f"Suspicious file extension detected: {extension}"
            )

        # 2. Check hidden filenames
        if filename_lower.startswith(".") and extension:
            if extension in SUSPICIOUS_EXTENSIONS:
                findings.append(
                    "Attachment uses a hidden filename"
                )

        # 3. Check multiple extensions
        filename_parts = filename_lower.split(".")

        if len(filename_parts) > 2:
            earlier_extensions = [
                "." + part
                for part in filename_parts[1:-1]
            ]

            if any(
                ext in SUSPICIOUS_EXTENSIONS
                for ext in earlier_extensions
            ):
                findings.append(
                    "Attachment contains a suspicious double extension"
                )

        # 4. Check MIME type mismatch
        expected_types = EXPECTED_MIME_TYPES.get(extension)

        if (
            expected_types
            and content_type
            and content_type not in expected_types
        ):
            findings.append(
                "File extension and declared MIME type do not match"
            )

        # Determine attachment status
        suspicious = bool(findings)

        status = (
            "Suspicious indicators detected"
            if suspicious
            else "No suspicious indicators detected"
        )

        analyzed_attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size": size,
            "suspicious": suspicious,
            "findings": findings,
            "status": status
        })

    return {
        "total_attachments": len(analyzed_attachments),
        "attachments": analyzed_attachments
    }
