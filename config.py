
import os


class Config:

    # Application secret key
    SECRET_KEY = os.getenv("SECRET_KEY")

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///phishlens.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Maximum uploaded file size: 5 MB
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    # Session cookie security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Enable only when running behind HTTPS
    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    )

    # CSRF protection
    WTF_CSRF_ENABLED = True

    # Session lifetime: 30 minutes
    PERMANENT_SESSION_LIFETIME = 1800

    # Disable unnecessary information
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True
    }
