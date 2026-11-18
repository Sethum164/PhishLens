
from datetime import datetime, timedelta

from app.extensions import db
from app.models import Investigation, User


def create_investigation(
    user_id,
    risk_score=50,
    risk_level="Medium",
    status="New",
    days_ago=0
):
    investigation = Investigation(
        user_id=user_id,
        risk_score=risk_score,
        risk_level=risk_level,
        status=status,
        created_at=datetime.now() - timedelta(days=days_ago)
    )

    db.session.add(investigation)
    db.session.commit()

    return investigation


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.location


def test_dashboard_loads_for_authenticated_user(logged_in_client):
    response = logged_in_client.get("/dashboard")

    assert response.status_code == 200
    assert b"SOC Command Center" in response.data

def test_dashboard_initially_shows_zero_investigations(
    logged_in_client
):
    response = logged_in_client.get("/dashboard")

    assert response.status_code == 200
    assert b"0" in response.data


def test_dashboard_displays_investigation_statistics(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        create_investigation(
            test_user,
            risk_score=90,
            risk_level="Critical",
            status="In Progress"
        )

        create_investigation(
            test_user,
            risk_score=40,
            risk_level="Medium",
            status="False Positive"
        )

    response = logged_in_client.get("/dashboard")

    assert response.status_code == 200
    assert b"Critical" in response.data
    assert b"Medium" in response.data
    assert b"In Progress" in response.data
    assert b"False Positive" in response.data


def test_dashboard_filters_other_users_investigations(
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
            username="otheruser",
            email="other@example.com"
        )

        other_user.set_password("OtherPassword123")

        db.session.add(other_user)
        db.session.commit()

        create_investigation(
            other_user.id,
            risk_score=100,
            risk_level="Critical"
        )

    response = logged_in_client.get("/dashboard")

    assert response.status_code == 200

    # Only the logged-in user's risk score should appear.
    assert b"80.00" in response.data
    assert b"100.00" not in response.data


def test_dashboard_accepts_valid_date_filters(logged_in_client):
    for period in ["7", "30", "90", "all"]:
        response = logged_in_client.get(
            f"/dashboard?period={period}"
        )

        assert response.status_code == 200


def test_dashboard_invalid_date_filter_defaults_to_all(
    logged_in_client
):
    response = logged_in_client.get(
        "/dashboard?period=invalid"
    )

    assert response.status_code == 200
    assert b"All Time" in response.data


def test_dashboard_last_seven_days_filter(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        create_investigation(
            test_user,
            risk_score=80,
            risk_level="High",
            days_ago=2
        )

        create_investigation(
            test_user,
            risk_score=90,
            risk_level="Critical",
            days_ago=10
        )

    response = logged_in_client.get("/dashboard?period=7")

    assert response.status_code == 200
    assert b"Last 7 Days" in response.data
