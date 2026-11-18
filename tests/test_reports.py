
from app.extensions import db
from app.models import Investigation, User


def create_investigation(
    user_id,
    risk_score=75,
    risk_level="High",
    status="New",
    days_ago=0
):
    from datetime import datetime, timedelta

    investigation = Investigation(
        user_id=user_id,
        sender="security@example.com",
        recipient="analyst@example.com",
        subject="Test Security Email",
        risk_score=risk_score,
        risk_level=risk_level,
        status=status,
        analyst_notes="Test investigation notes.",
        analysis_results={
            "from": "security@example.com",
            "to": "analyst@example.com",
            "subject": "Test Security Email",
            "urls": ["https://example.com/login"],
            "domains": ["example.com"],
            "ip_addresses": [],
            "risk_analysis": {
                "risk_factors": []
            }
        },
        created_at=datetime.now() - timedelta(days=days_ago)
    )

    db.session.add(investigation)
    db.session.commit()

    return investigation.id


def assert_valid_pdf(response):
    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF")
    assert len(response.data) > 1000


def test_individual_report_requires_login(client):
    response = client.get("/investigation/1/report")

    assert response.status_code == 302
    assert "/login" in response.location


def test_individual_report_generates_pdf(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        investigation_id = create_investigation(test_user)

    response = logged_in_client.get(
        f"/investigation/{investigation_id}/report"
    )

    assert_valid_pdf(response)
    assert (
        f"PhishLens_Investigation_{investigation_id}.pdf"
        in response.headers["Content-Disposition"]
    )


def test_user_cannot_download_another_users_report(
    app,
    logged_in_client
):
    with app.app_context():
        other_user = User(
            username="reportuser",
            email="reportuser@example.com"
        )
        other_user.set_password("ReportPassword123")

        db.session.add(other_user)
        db.session.commit()

        investigation_id = create_investigation(other_user.id)

    response = logged_in_client.get(
        f"/investigation/{investigation_id}/report"
    )

    assert response.status_code == 404


def test_dashboard_report_requires_login(client):
    response = client.get("/dashboard/report")

    assert response.status_code == 302
    assert "/login" in response.location


def test_dashboard_report_generates_pdf(
    logged_in_client
):
    response = logged_in_client.get("/dashboard/report")

    assert_valid_pdf(response)

    assert (
        "PhishLens_SOC_Dashboard_Report.pdf"
        in response.headers["Content-Disposition"]
    )


def test_dashboard_report_accepts_valid_date_filters(
    logged_in_client
):
    for period in ["7", "30", "90", "all"]:
        response = logged_in_client.get(
            f"/dashboard/report?period={period}"
        )

        assert_valid_pdf(response)


def test_dashboard_report_invalid_period_defaults_to_all(
    logged_in_client
):
    response = logged_in_client.get(
        "/dashboard/report?period=invalid"
    )

    assert_valid_pdf(response)


def test_dashboard_report_uses_logged_in_users_data(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        create_investigation(
            test_user,
            risk_score=80,
            risk_level="High"
        )

        other_user = User(
            username="anotherreportuser",
            email="anotherreportuser@example.com"
        )
        other_user.set_password("AnotherPassword123")

        db.session.add(other_user)
        db.session.commit()

        create_investigation(
            other_user.id,
            risk_score=100,
            risk_level="Critical"
        )

    response = logged_in_client.get("/dashboard/report")

    assert_valid_pdf(response)
