
from app.extensions import db
from app.models import User


def test_register_page_loads(client):
    response = client.get("/register")

    assert response.status_code == 200


def test_login_page_loads(client):
    response = client.get("/login")

    assert response.status_code == 200


def test_user_registration(client, app):
    response = client.post(
        "/register",
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "StrongPass123",
            "confirm_password": "StrongPass123"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(
            username="newuser"
        ).first()

        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.check_password("StrongPass123")


def test_registration_rejects_short_password(client, app):
    response = client.post(
        "/register",
        data={
            "username": "shortuser",
            "email": "short@example.com",
            "password": "123",
            "confirm_password": "123"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(
            username="shortuser"
        ).first()

        assert user is None


def test_registration_rejects_password_mismatch(client, app):
    client.post(
        "/register",
        data={
            "username": "mismatchuser",
            "email": "mismatch@example.com",
            "password": "StrongPass123",
            "confirm_password": "DifferentPass123"
        },
        follow_redirects=True
    )

    with app.app_context():
        user = User.query.filter_by(
            username="mismatchuser"
        ).first()

        assert user is None


def test_login_with_username(client, test_user):
    response = client.post(
        "/login",
        data={
            "username_or_email": "testuser",
            "password": "TestPassword123"
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Login successful" in response.data


def test_login_with_email(client, test_user):
    response = client.post(
        "/login",
        data={
            "username_or_email": "test@example.com",
            "password": "TestPassword123"
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Login successful" in response.data


def test_login_rejects_wrong_password(client, test_user):
    response = client.post(
        "/login",
        data={
            "username_or_email": "testuser",
            "password": "WrongPassword123"
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Invalid username/email or password" in response.data


def test_logout(client, logged_in_client):
    response = logged_in_client.post(
        "/logout",
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"You have been logged out" in response.data
