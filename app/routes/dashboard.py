
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from app.models import Investigation
from app.extensions import db


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():

    # Available date filters
    date_options = {
        "7": 7,
        "30": 30,
        "90": 90
    }

    selected_period = request.args.get("period", "all")

    # Validate selected period
    if selected_period not in ["7", "30", "90", "all"]:
        selected_period = "all"

    # Get investigations belonging to the logged-in analyst
    investigations = Investigation.query.filter_by(
        user_id=current_user.id
    )

    # Apply date filter
    if selected_period in date_options:

        cutoff_date = datetime.now() - timedelta(
            days=date_options[selected_period]
        )

        investigations = investigations.filter(
            Investigation.created_at >= cutoff_date
        )

    # Total investigations
    total_investigations = investigations.count()

    # Risk Score Overview
    average_risk_score = investigations.with_entities(
        db.func.avg(Investigation.risk_score)
    ).scalar()

    highest_risk_score = investigations.with_entities(
        db.func.max(Investigation.risk_score)
    ).scalar()

    average_risk_score = round(average_risk_score or 0, 2)
    highest_risk_score = highest_risk_score or 0

    # Risk level statistics
    critical_count = investigations.filter_by(
        risk_level="Critical"
    ).count()

    high_count = investigations.filter_by(
        risk_level="High"
    ).count()

    medium_count = investigations.filter_by(
        risk_level="Medium"
    ).count()

    low_count = investigations.filter_by(
        risk_level="Low"
    ).count()

    # Investigation status statistics
    new_count = investigations.filter_by(
        status="New"
    ).count()

    in_progress_count = investigations.filter_by(
        status="In Progress"
    ).count()

    resolved_count = investigations.filter_by(
        status="Resolved"
    ).count()

    false_positive_count = investigations.filter_by(
        status="False Positive"
    ).count()

    # Risk Level vs Investigation Status statistics
    risk_levels = ["Critical", "High", "Medium", "Low"]

    statuses = [
        "New",
        "In Progress",
        "Resolved",
        "False Positive"
    ]

    risk_status_counts = {
        risk: {status: 0 for status in statuses}
        for risk in risk_levels
    }

    status_results = investigations.with_entities(
        Investigation.risk_level,
        Investigation.status,
        db.func.count(Investigation.id)
    ).group_by(
        Investigation.risk_level,
        Investigation.status
    ).all()

    for risk, status, count in status_results:

        if risk in risk_status_counts and status in statuses:
            risk_status_counts[risk][status] = count

    # Risk Score Trend Data
    risk_trend_results = investigations.with_entities(
        Investigation.created_at,
        Investigation.risk_score
    ).order_by(
        Investigation.created_at.asc(),
        Investigation.id.asc()
    ).all()

    risk_trend_labels = [
        item.created_at.strftime("%Y-%m-%d %H:%M")
        if item.created_at else "Unknown"
        for item in risk_trend_results
    ]

    risk_trend_scores = [
        item.risk_score
        for item in risk_trend_results
    ]

    # Get the latest five investigations
    recent_investigations = investigations.order_by(
        Investigation.created_at.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        total_investigations=total_investigations,
        average_risk_score=average_risk_score,
        highest_risk_score=highest_risk_score,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        new_count=new_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count,
        false_positive_count=false_positive_count,
        risk_status_counts=risk_status_counts,
        risk_levels=risk_levels,
        statuses=statuses,
        risk_trend_labels=risk_trend_labels,
        risk_trend_scores=risk_trend_scores,
        recent_investigations=recent_investigations,
        selected_period=selected_period
    )
