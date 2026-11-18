
from io import BytesIO

from app.extensions import db
from app.models import Investigation, User


VALID_EMAIL = (
    b"From: security@example.com\r\n"
    b"To: analyst@example.com\r\n"
    b"Subject: Account Security Verification\r\n"
    b"Date: Tue, 18 Nov 2026 10:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Please review your account security settings.\r\n"
)


def create_investigation(user_id):
    investigation = Investigation(
        user_id=user_id,
        sender="security@example.com",
        recipient="analyst@example.com",
        subject="Test Security Email",
        risk_score=75,
        risk_level="High",
        status="New",
        analysis_results={}
    )

    db.session.add(investigation)
    db.session.commit()

    return investigation.id


def test_analyze_page_requires_login(client):
    response = client.get("/analyze")

    assert response.status_code == 302
    assert "/login" in response.location


def test_analyze_page_loads(logged_in_client):
    response = logged_in_client.get("/analyze")

    assert response.status_code == 200


def test_history_page_requires_login(client):
    response = client.get("/history")

    assert response.status_code == 302
    assert "/login" in response.location


def test_history_page_loads(logged_in_client):
    response = logged_in_client.get("/history")

    assert response.status_code == 200


def test_upload_rejects_missing_file(logged_in_client):
    response = logged_in_client.post(
        "/analyze",
        data={}
    )

    assert response.status_code == 302


def test_upload_rejects_unsupported_file(logged_in_client):
    response = logged_in_client.post(
        "/analyze",
        data={
            "email_file": (
                BytesIO(b"test content"),
                "document.txt"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 302


def test_upload_rejects_empty_email(logged_in_client):
    response = logged_in_client.post(
        "/analyze",
        data={
            "email_file": (
                BytesIO(b""),
                "empty.eml"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 302


def test_upload_rejects_file_over_5mb(logged_in_client):
    large_email = b"A" * (5 * 1024 * 1024 + 1)

    response = logged_in_client.post(
        "/analyze",
        data={
            "email_file": (
                BytesIO(large_email),
                "large.eml"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 413


def test_valid_email_upload_saves_investigation(
    app,
    logged_in_client,
    test_user
):
    response = logged_in_client.post(
        "/analyze",
        data={
            "email_file": (
                BytesIO(VALID_EMAIL),
                "sample.eml"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 200

    with app.app_context():
        investigation = Investigation.query.filter_by(
            user_id=test_user
        ).first()

        assert investigation is not None
        assert investigation.sender == "security@example.com"
        assert investigation.recipient == "analyst@example.com"
        assert investigation.subject == "Account Security Verification"
        assert investigation.status == "New"
        assert investigation.analysis_results is not None


def test_investigation_details_requires_login(client):
    response = client.get("/investigation/1")

    assert response.status_code == 302
    assert "/login" in response.location


def test_user_cannot_view_another_users_investigation(
    app,
    logged_in_client
):
    with app.app_context():
        other_user = User(
            username="otheranalyst",
            email="otheranalyst@example.com"
        )
        other_user.set_password("OtherPassword123")

        db.session.add(other_user)
        db.session.commit()

        investigation_id = create_investigation(other_user.id)

    response = logged_in_client.get(
        f"/investigation/{investigation_id}"
    )

    assert response.status_code == 404


def test_update_investigation_status(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        investigation_id = create_investigation(test_user)

    response = logged_in_client.post(
        f"/investigation/{investigation_id}/update",
        data={
            "status": "In Progress",
            "analyst_notes": "Investigating suspicious email."
        }
    )

    assert response.status_code == 302

    with app.app_context():
        investigation = db.session.get(
            Investigation,
            investigation_id
        )

        assert investigation.status == "In Progress"
        assert investigation.analyst_notes == (
            "Investigating suspicious email."
        )


def test_update_rejects_invalid_status(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        investigation_id = create_investigation(test_user)

    response = logged_in_client.post(
        f"/investigation/{investigation_id}/update",
        data={
            "status": "Hacked",
            "analyst_notes": "Test"
        }
    )

    assert response.status_code == 302

    with app.app_context():
        investigation = db.session.get(
            Investigation,
            investigation_id
        )

        assert investigation.status == "New"


def test_update_rejects_notes_over_5000_characters(
    app,
    logged_in_client,
    test_user
):
    with app.app_context():
        investigation_id = create_investigation(test_user)

    response = logged_in_client.post(
        f"/investigation/{investigation_id}/update",
        data={
            "status": "In Progress",
            "analyst_notes": "A" * 5001
        }
    )

    assert response.status_code == 302

    with app.app_context():
        investigation = db.session.get(
            Investigation,
            investigation_id
        )

        assert investigation.status == "New"
        assert investigation.analyst_notes is None
