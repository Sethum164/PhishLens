
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture
def app():

    test_app = create_app()

    test_app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_DATABASE_URI="sqlite://",
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
        RATELIMIT_ENABLED=False
    )

    with test_app.app_context():

        db.create_all()

        yield test_app

        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):

    return app.test_client()


@pytest.fixture
def test_user(app):

    with app.app_context():

        user = User(
            username="testuser",
            email="test@example.com"
        )

        user.set_password("TestPassword123")

        db.session.add(user)
        db.session.commit()

        user_id = user.id

    return user_id


@pytest.fixture
def logged_in_client(client, test_user):

    client.post(
        "/login",
        data={
            "username_or_email": "testuser",
            "password": "TestPassword123"
        }
    )

    return client
