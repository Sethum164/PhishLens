from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_login import login_user, logout_user, current_user

from app.extensions import db, limiter
from app.models import User


auth_bp = Blueprint("auth", __name__)


# --------------------------------------------------
# USER REGISTRATION
# --------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Please complete all required fields.", "danger")
            return redirect(url_for("auth.register"))

        if len(username) > 80 or len(email) > 120:
            flash("Username or email is too long.", "danger")
            return redirect(url_for("auth.register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("auth.register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("auth.register"))

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:
            flash("Username or email already exists.", "danger")
            return redirect(url_for("auth.register"))

        new_user = User(
            username=username,
            email=email
        )

        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        flash("Account created successfully.", "success")

        return redirect(url_for("dashboard.dashboard"))

    return render_template("register.html")


# --------------------------------------------------
# USER LOGIN
# --------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":

        username_or_email = request.form.get(
            "username_or_email", ""
        ).strip()

        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == username_or_email) |
            (User.email == username_or_email.lower())
        ).first()

        if user and user.check_password(password):

            login_user(user)

            flash("Login successful.", "success")

            return redirect(url_for("dashboard.dashboard"))

        flash("Invalid username/email or password.", "danger")

    return render_template("login.html")


# --------------------------------------------------
# USER LOGOUT
# --------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
def logout():

    logout_user()

    flash("You have been logged out.", "info")

    return redirect(url_for("auth.login"))
