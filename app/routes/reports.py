
from io import BytesIO
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from flask import Blueprint, make_response, request
from flask_login import login_required, current_user

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)

from app.models import Investigation
from app.extensions import db

reports_bp = Blueprint("reports", __name__)


# --------------------------------------------------
# BRAND COLOURS
# --------------------------------------------------

NAVY = colors.HexColor("#26374A")
BLUE = colors.HexColor("#315A7D")
LIGHT_BLUE = colors.HexColor("#EAF1F7")
LIGHT_GREY = colors.HexColor("#F3F5F7")
DARK_GREY = colors.HexColor("#333333")
RED = colors.HexColor("#DC3545")
ORANGE = colors.HexColor("#FD7E14")
CYAN = colors.HexColor("#0DCAF0")
GREEN = colors.HexColor("#198754")


# --------------------------------------------------
# PDF HEADER AND FOOTER
# --------------------------------------------------

def draw_page_header_footer(canvas, document):

    canvas.saveState()

    page_width, page_height = A4

    canvas.setFillColor(NAVY)
    canvas.rect(
        0,
        page_height - 22 * mm,
        page_width,
        22 * mm,
        fill=1,
        stroke=0
    )

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 17)
    canvas.drawString(
        18 * mm,
        page_height - 13 * mm,
        "PhishLens"
    )

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        page_width - 18 * mm,
        page_height - 13 * mm,
        "SOC SECURITY REPORT"
    )

    canvas.setStrokeColor(NAVY)
    canvas.setLineWidth(0.7)
    canvas.line(
        18 * mm,
        16 * mm,
        page_width - 18 * mm,
        16 * mm
    )

    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(
        18 * mm,
        10 * mm,
        "CONFIDENTIAL - PHISHLENS SECURITY REPORT"
    )

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        page_width - 18 * mm,
        10 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# --------------------------------------------------
# PDF TABLE STYLE
# --------------------------------------------------

def create_table_style():

    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4,
         colors.HexColor("#D0D5DA")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            LIGHT_GREY
        ])
    ])


# --------------------------------------------------
# SHARED PDF HELPERS
# --------------------------------------------------

def create_pdf_styles():

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=24,
        textColor=NAVY,
        alignment=1,
        spaceAfter=8
    )

    heading_style = ParagraphStyle(
        "ProfessionalHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=NAVY,
        spaceBefore=12,
        spaceAfter=8,
        keepWithNext=True
    )

    normal_style = ParagraphStyle(
        "ProfessionalBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=DARK_GREY,
        spaceAfter=4
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=normal_style,
        fontSize=8,
        leading=11
    )

    return title_style, heading_style, normal_style, small_style


def safe_text(value):

    if value is None or value == "":
        return "Not available"

    return escape(str(value))


def add_section(story, title, heading_style):

    story.append(Paragraph(title, heading_style))
    story.append(HRFlowable(
        width="100%",
        thickness=1,
        color=BLUE,
        spaceAfter=8
    ))


# --------------------------------------------------
# GENERATE INVESTIGATION REPORT
# --------------------------------------------------

@reports_bp.route("/investigation/<int:investigation_id>/report")
@login_required
def generate_report(investigation_id):

    investigation = Investigation.query.filter_by(
        id=investigation_id,
        user_id=current_user.id
    ).first_or_404()

    email = investigation.analysis_results or {}

    if not isinstance(email, dict):
        email = {}

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=30 * mm,
        bottomMargin=23 * mm
    )

    title_style, heading_style, normal_style, small_style = (
        create_pdf_styles()
    )

    story = []

    story.append(Spacer(1, 5))

    story.append(Paragraph(
        "Phishing Email Investigation Report",
        title_style
    ))

    story.append(Paragraph(
        "Security Operations Centre | Email Threat Analysis",
        ParagraphStyle(
            "Subtitle",
            parent=normal_style,
            alignment=1,
            textColor=BLUE,
            fontSize=9
        )
    ))

    story.append(Spacer(1, 12))

    metadata = [
        ["REPORT DATE", "INVESTIGATION ID", "ANALYST"],
        [
            datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            ),
            f"#{investigation.id}",
            safe_text(current_user.username)
        ]
    ]

    metadata_table = Table(
        metadata,
        colWidths=[55 * mm, 55 * mm, 55 * mm]
    )

    metadata_table.setStyle(create_table_style())

    story.append(metadata_table)
    story.append(Spacer(1, 15))

    # 1. Risk Assessment

    add_section(
        story,
        "1. Overall Risk Assessment",
        heading_style
    )

    risk_level = investigation.risk_level

    risk_colors = {
        "Critical": RED,
        "High": ORANGE,
        "Medium": CYAN,
        "Low": GREEN
    }

    risk_color = risk_colors.get(risk_level, colors.grey)

    risk_data = [
        ["RISK SCORE", "RISK LEVEL", "INVESTIGATION STATUS"],
        [
            f"{investigation.risk_score}/100",
            safe_text(risk_level),
            safe_text(investigation.status)
        ]
    ]

    risk_table = Table(
        risk_data,
        colWidths=[45 * mm, 45 * mm, 75 * mm],
        rowHeights=[12 * mm, 18 * mm]
    )

    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (0, 1), LIGHT_GREY),
        ("BACKGROUND", (1, 1), (1, 1), risk_color),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.white),
        ("BACKGROUND", (2, 1), (2, 1), LIGHT_GREY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 11),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(risk_table)
    story.append(Spacer(1, 12))

    # 2. Email Information

    add_section(
        story,
        "2. Email Information",
        heading_style
    )

    email_fields = [
        ["Field", "Value"],
        ["From", safe_text(email.get("from"))],
        ["To", safe_text(email.get("to"))],
        ["Subject", safe_text(email.get("subject"))],
        ["Date", safe_text(email.get("date"))],
        ["Reply-To", safe_text(email.get("reply_to"))],
        ["Return-Path", safe_text(email.get("return_path"))],
        ["Message-ID", safe_text(email.get("message_id"))]
    ]

    email_table = Table(
        email_fields,
        colWidths=[45 * mm, 120 * mm],
        repeatRows=1
    )

    email_table.setStyle(create_table_style())

    story.append(email_table)
    story.append(Spacer(1, 12))

    # 3. Detected Risk Factors

    add_section(
        story,
        "3. Detected Risk Factors",
        heading_style
    )

    risk_analysis = email.get("risk_analysis", {})

    if not isinstance(risk_analysis, dict):
        risk_analysis = {}

    risk_factors = risk_analysis.get("risk_factors", [])

    if isinstance(risk_factors, list) and risk_factors:

        for item in risk_factors:

            if isinstance(item, dict):

                factor = safe_text(
                    item.get("factor", "Unknown risk factor")
                )

                points = safe_text(item.get("points", 0))

                factor_content = [
                    Paragraph(
                        f"<b>{factor}</b> - {points} points",
                        normal_style
                    )
                ]

                if item.get("url"):
                    factor_content.append(Paragraph(
                        f"URL: {safe_text(item.get('url'))}",
                        small_style
                    ))

                if item.get("filename"):
                    factor_content.append(Paragraph(
                        f"Filename: {safe_text(item.get('filename'))}",
                        small_style
                    ))

                findings = item.get("findings", [])

                if isinstance(findings, list):

                    for finding in findings:
                        factor_content.append(Paragraph(
                            f"- {safe_text(finding)}",
                            small_style
                        ))

                risk_card = Table(
                    [[factor_content]],
                    colWidths=[165 * mm]
                )

                risk_card.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
                    ("BOX", (0, 0), (-1, -1), 0.5,
                     colors.HexColor("#D0D5DA")),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, BLUE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
                ]))

                story.append(risk_card)
                story.append(Spacer(1, 6))

            else:
                story.append(Paragraph(
                    safe_text(item),
                    normal_style
                ))

    else:
        story.append(Paragraph(
            "No risk factors detected.",
            normal_style
        ))

    story.append(Spacer(1, 10))

    # 4. Extracted Indicators of Compromise

    add_section(
        story,
        "4. Extracted Indicators of Compromise (IOCs)",
        heading_style
    )

    ioc_sections = [
        ("URLs", email.get("urls", [])),
        ("Domains", email.get("domains", [])),
        ("IP Addresses", email.get("ip_addresses", []))
    ]

    for label, values in ioc_sections:

        story.append(Paragraph(
            f"<b>{label}</b>",
            normal_style
        ))

        if isinstance(values, list) and values:

            for value in values:
                story.append(Paragraph(
                    f"- {safe_text(value)}",
                    small_style
                ))

        else:
            story.append(Paragraph(
                "None detected.",
                small_style
            ))

        story.append(Spacer(1, 5))

    # 5. Attachment Analysis

    add_section(
        story,
        "5. Attachment Analysis",
        heading_style
    )

    attachment_analysis = email.get(
        "attachment_analysis",
        {}
    )

    if isinstance(attachment_analysis, dict):

        attachments = attachment_analysis.get(
            "attachments",
            []
        )

        total_attachments = attachment_analysis.get(
            "total_attachments",
            len(attachments) if isinstance(attachments, list) else 0
        )

    else:

        attachments = email.get("attachments", [])

        total_attachments = (
            len(attachments)
            if isinstance(attachments, list)
            else 0
        )

    if isinstance(attachments, list) and attachments:

        story.append(Paragraph(
            f"<b>Total Attachments:</b> {safe_text(total_attachments)}",
            normal_style
        ))

        attachment_data = [
            ["Filename", "Content Type", "Size", "Status"]
        ]

        for attachment in attachments:

            if isinstance(attachment, dict):

                filename = attachment.get("filename", "Unknown")
                content_type = attachment.get(
                    "content_type", "Unknown"
                )
                size = attachment.get("size", 0)
                status = attachment.get(
                    "status", "Not analyzed"
                )

            else:

                filename = str(attachment)
                content_type = "Unknown"
                size = 0
                status = "Not analyzed"

            attachment_data.append([
                safe_text(filename),
                safe_text(content_type),
                f"{safe_text(size)} bytes",
                safe_text(status)
            ])

        attachment_table = Table(
            attachment_data,
            colWidths=[45 * mm, 55 * mm, 25 * mm, 40 * mm],
            repeatRows=1
        )

        attachment_table.setStyle(create_table_style())

        for row_index in range(1, len(attachment_data)):

            status_value = attachment_data[row_index][3].lower()

            if "suspicious" in status_value:
                attachment_table.setStyle(TableStyle([
                    ("TEXTCOLOR", (3, row_index), (3, row_index), RED),
                    ("FONTNAME", (3, row_index), (3, row_index),
                     "Helvetica-Bold")
                ]))

        story.append(attachment_table)

    else:

        story.append(Paragraph(
            "No attachments detected.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # 6. Analyst Investigation Notes

    add_section(
        story,
        "6. Analyst Investigation Notes",
        heading_style
    )

    notes = investigation.analyst_notes

    if notes:

        safe_notes = safe_text(notes).replace("\n", "<br/>")

        story.append(Paragraph(
            safe_notes,
            normal_style
        ))

    else:

        story.append(Paragraph(
            "No analyst notes added.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # 7. Disclaimer

    add_section(
        story,
        "7. Disclaimer",
        heading_style
    )

    story.append(Paragraph(
        "The PhishLens risk score is based on heuristic "
        "security indicators detected during email analysis. "
        "It is an investigative aid and does not represent "
        "a guaranteed probability that an email is malicious. "
        "Analysts should verify findings using additional "
        "security evidence.",
        small_style
    ))

    # Generate PDF

    document.build(
        story,
        onFirstPage=draw_page_header_footer,
        onLaterPages=draw_page_header_footer
    )

    pdf_data = buffer.getvalue()
    buffer.close()

    response = make_response(pdf_data)

    response.headers["Content-Type"] = "application/pdf"

    response.headers["Content-Disposition"] = (
        f"attachment; filename=PhishLens_Investigation_{investigation.id}.pdf"
    )

    return response


# --------------------------------------------------
# GENERATE SOC DASHBOARD PDF REPORT
# --------------------------------------------------

@reports_bp.route("/dashboard/report")
@login_required
def generate_dashboard_report():

    # Available date filters
    date_options = {
        "7": 7,
        "30": 30,
        "90": 90
    }

    selected_period = request.args.get("period", "all")

    if selected_period not in ["7", "30", "90", "all"]:
        selected_period = "all"

    # Get investigations belonging to the logged-in analyst
    investigations = Investigation.query.filter_by(
        user_id=current_user.id
    )

    # Apply the selected date filter
    if selected_period in date_options:

        cutoff_date = datetime.now() - timedelta(
            days=date_options[selected_period]
        )

        investigations = investigations.filter(
            Investigation.created_at >= cutoff_date
        )

    # Calculate statistics
    total_investigations = investigations.count()

    average_risk_score = investigations.with_entities(
        db.func.avg(Investigation.risk_score)
    ).scalar()

    highest_risk_score = investigations.with_entities(
        db.func.max(Investigation.risk_score)
    ).scalar()

    average_risk_score = round(average_risk_score or 0, 2)
    highest_risk_score = highest_risk_score or 0

    risk_levels = ["Critical", "High", "Medium", "Low"]

    statuses = [
        "New",
        "In Progress",
        "Resolved",
        "False Positive"
    ]

    risk_counts = {
        risk: investigations.filter_by(
            risk_level=risk
        ).count()
        for risk in risk_levels
    }

    status_counts = {
        status: investigations.filter_by(
            status=status
        ).count()
        for status in statuses
    }

    # Risk level vs status summary
    risk_status_counts = {
        risk: {status: 0 for status in statuses}
        for risk in risk_levels
    }

    status_results = investigations.with_entities(
        Investigation.risk_level,
        Investigation.status,
        __import__("app.extensions", fromlist=["db"]).db.func.count(
            Investigation.id
        )
    ).group_by(
        Investigation.risk_level,
        Investigation.status
    ).all()

    for risk, status, count in status_results:

        if risk in risk_status_counts and status in statuses:
            risk_status_counts[risk][status] = count

    # Create PDF
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=30 * mm,
        bottomMargin=23 * mm
    )

    title_style, heading_style, normal_style, small_style = (
        create_pdf_styles()
    )

    story = []

    story.append(Spacer(1, 5))

    story.append(Paragraph(
        "SOC Dashboard Analytics Report",
        title_style
    ))

    story.append(Paragraph(
        "PhishLens | Security Operations Centre",
        ParagraphStyle(
            "DashboardSubtitle",
            parent=normal_style,
            alignment=1,
            textColor=BLUE,
            fontSize=9
        )
    ))

    story.append(Spacer(1, 12))

    # Report metadata
    period_labels = {
        "all": "All Time",
        "7": "Last 7 Days",
        "30": "Last 30 Days",
        "90": "Last 90 Days"
    }

    metadata = [
        ["REPORT DATE", "DATE RANGE", "ANALYST"],
        [
            datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            ),
            period_labels[selected_period],
            safe_text(current_user.username)
        ]
    ]

    metadata_table = Table(
        metadata,
        colWidths=[55 * mm, 55 * mm, 55 * mm]
    )

    metadata_table.setStyle(create_table_style())

    story.append(metadata_table)
    story.append(Spacer(1, 15))

    # 1. Overview
    add_section(
        story,
        "1. Investigation Overview",
        heading_style
    )

    overview_data = [
        ["Metric", "Value"],
        ["Total Investigations", str(total_investigations)],
        ["Average Risk Score", f"{average_risk_score}/100"],
        ["Highest Risk Score", f"{highest_risk_score}/100"]
    ]

    overview_table = Table(
        overview_data,
        colWidths=[90 * mm, 75 * mm]
    )

    overview_table.setStyle(create_table_style())

    story.append(overview_table)
    story.append(Spacer(1, 12))

    # 2. Risk Distribution
    add_section(
        story,
        "2. Risk Level Distribution",
        heading_style
    )

    risk_data = [["Risk Level", "Number of Investigations"]]

    for risk in risk_levels:
        risk_data.append([
            risk,
            str(risk_counts[risk])
        ])

    risk_table = Table(
        risk_data,
        colWidths=[90 * mm, 75 * mm]
    )

    risk_table.setStyle(create_table_style())

    story.append(risk_table)
    story.append(Spacer(1, 12))

    # 3. Status Distribution
    add_section(
        story,
        "3. Investigation Status Distribution",
        heading_style
    )

    status_data = [["Investigation Status", "Number of Investigations"]]

    for status in statuses:
        status_data.append([
            status,
            str(status_counts[status])
        ])

    status_table = Table(
        status_data,
        colWidths=[90 * mm, 75 * mm]
    )

    status_table.setStyle(create_table_style())

    story.append(status_table)
    story.append(Spacer(1, 12))

    # 4. Risk vs Status Summary
    add_section(
        story,
        "4. Risk Level vs Investigation Status",
        heading_style
    )

    summary_data = [
        ["Risk Level"] + statuses + ["Total"]
    ]

    for risk in risk_levels:

        row_total = sum(
            risk_status_counts[risk].values()
        )

        row = [risk]

        for status in statuses:
            row.append(
                str(risk_status_counts[risk][status])
            )

        row.append(str(row_total))

        summary_data.append(row)

    total_row = ["Total"]

    for status in statuses:
        total_row.append(str(status_counts[status]))

    total_row.append(str(total_investigations))

    summary_data.append(total_row)

    summary_table = Table(
        summary_data,
        colWidths=[
            27 * mm,
            31 * mm,
            31 * mm,
            31 * mm,
            31 * mm,
            18 * mm
        ],
        repeatRows=1
    )

    summary_table.setStyle(create_table_style())

    story.append(summary_table)
    story.append(Spacer(1, 15))

    # 5. Disclaimer
    add_section(
        story,
        "5. Report Disclaimer",
        heading_style
    )

    story.append(Paragraph(
        "This report summarizes investigations recorded in "
        "the PhishLens platform for the selected date range. "
        "Risk scores are based on heuristic security indicators "
        "and should be treated as investigative guidance rather "
        "than a guaranteed probability of malicious activity.",
        small_style
    ))

    # Generate PDF
    document.build(
        story,
        onFirstPage=draw_page_header_footer,
        onLaterPages=draw_page_header_footer
    )

    pdf_data = buffer.getvalue()
    buffer.close()

    response = make_response(pdf_data)

    response.headers["Content-Type"] = "application/pdf"

    response.headers["Content-Disposition"] = (
        "attachment; filename=PhishLens_SOC_Dashboard_Report.pdf"
    )

    return response
