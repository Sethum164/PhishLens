
from flask import (
    Blueprint,
    render_template,
    request,
    flash,
    redirect,
    url_for
)

from flask_login import login_required, current_user

from app.extensions import db
from app.models import Investigation

# Import Email Parser
from app.services.email_parser import parse_email


# Create analyzer Blueprint
analyzer_bp = Blueprint("analyzer", __name__)


# Allowed investigation statuses
ALLOWED_STATUSES = {
    "New",
    "In Progress",
    "Resolved",
    "False Positive"
}


# Email analysis page
@analyzer_bp.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():

    if request.method == "POST":

        email_file = request.files.get("email_file")

        if not email_file or email_file.filename == "":
            flash("Please select an email file.", "danger")
            return redirect(url_for("analyzer.analyze"))

        if not email_file.filename.lower().endswith(".eml"):
            flash("Only .eml email files are allowed.", "danger")
            return redirect(url_for("analyzer.analyze"))

        email_data = email_file.stream.read(5 * 1024 * 1024 + 1)

        if not email_data:
            flash("The uploaded email file is empty.", "danger")
            return redirect(url_for("analyzer.analyze"))

        if len(email_data) > 5 * 1024 * 1024:
            flash("The email file exceeds the 5 MB limit.", "danger")
            return redirect(url_for("analyzer.analyze"))

        try:
            email_results = parse_email(email_data)

        except Exception:
            flash(
                "Unable to analyze this email. Please check the file format.",
                "danger"
            )
            return redirect(url_for("analyzer.analyze"))

        risk_analysis = email_results.get("risk_analysis", {})

        risk_score = risk_analysis.get("risk_score", 0)
        risk_level = risk_analysis.get("risk_level", "Low")

        investigation = Investigation(
            user_id=current_user.id,
            sender=email_results.get("from", ""),
            recipient=email_results.get("to", ""),
            subject=email_results.get("subject", ""),
            risk_score=risk_score,
            risk_level=risk_level,
            status="New",
            analysis_results=email_results
        )

        try:
            db.session.add(investigation)
            db.session.commit()

        except Exception:
            db.session.rollback()

            flash(
                "Email analysis completed, but the investigation could not be saved.",
                "danger"
            )

            return render_template(
                "results.html",
                email=email_results
            )

        email_results["investigation_id"] = investigation.id

        flash(
            f"Investigation #{investigation.id} saved successfully.",
            "success"
        )

        return render_template(
            "results.html",
            email=email_results
        )

    return render_template("upload.html")


# Investigation history page
@analyzer_bp.route("/history")
@login_required
def history():

    investigations = Investigation.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Investigation.created_at.desc()
    ).all()

    return render_template(
        "history.html",
        investigations=investigations
    )


# Individual investigation details page
@analyzer_bp.route("/investigation/<int:investigation_id>")
@login_required
def investigation_details(investigation_id):

    investigation = Investigation.query.filter_by(
        id=investigation_id,
        user_id=current_user.id
    ).first_or_404()

    email_results = investigation.analysis_results or {}

    return render_template(
        "investigation_details.html",
        investigation=investigation,
        email=email_results
    )


# Update investigation status and analyst notes
@analyzer_bp.route(
    "/investigation/<int:investigation_id>/update",
    methods=["POST"]
)
@login_required
def update_investigation(investigation_id):

    # Only allow the current analyst to update their own investigation
    investigation = Investigation.query.filter_by(
        id=investigation_id,
        user_id=current_user.id
    ).first_or_404()

    new_status = request.form.get("status", "").strip()
    analyst_notes = request.form.get("analyst_notes", "").strip()

    # Validate status
    if new_status not in ALLOWED_STATUSES:
        flash("Invalid investigation status.", "danger")
        return redirect(
            url_for(
                "analyzer.investigation_details",
                investigation_id=investigation.id
            )
        )

    # Validate notes length
    if len(analyst_notes) > 5000:
        flash("Analyst notes cannot exceed 5000 characters.", "danger")
        return redirect(
            url_for(
                "analyzer.investigation_details",
                investigation_id=investigation.id
            )
        )

    # Update database record
    investigation.status = new_status
    investigation.analyst_notes = analyst_notes

    try:
        db.session.commit()

    except Exception:
        db.session.rollback()
        flash("Unable to update the investigation.", "danger")

        return redirect(
            url_for(
                "analyzer.investigation_details",
                investigation_id=investigation.id
            )
        )

    flash("Investigation updated successfully.", "success")

    return redirect(
        url_for(
            "analyzer.investigation_details",
            investigation_id=investigation.id
        )
    )
