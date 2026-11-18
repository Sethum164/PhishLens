
from dotenv import load_dotenv

# Load environment variables before importing Config
load_dotenv()

from flask import Flask, render_template
from config import Config

from app.extensions import db, login_manager, csrf, limiter
from app.models import User

from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.analyzer import analyzer_bp
from app.routes.reports import reports_bp


def create_app():

    app = Flask(__name__)

    # Load application configuration
    app.config.from_object(Config)

    # Ensure SECRET_KEY is configured
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY is missing from .env")

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Flask-Login configuration
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):

        try:
            return db.session.get(User, int(user_id))

        except (ValueError, TypeError):
            return None

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analyzer_bp)
    app.register_blueprint(reports_bp)

    # HTTP security headers
    @app.after_request
    def add_security_headers(response):

        response.headers["X-Content-Type-Options"] = "nosniff"

        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "img-src 'self' data: https:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'; "
            "form-action 'self'"
        )

        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response

    # Home page
    @app.route("/")
    def home():
        return render_template("home.html")

    return app
