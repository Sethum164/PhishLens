
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db

from datetime import datetime, timezone


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    investigations = db.relationship(
        "Investigation",
        backref="analyst",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password,
            method="scrypt"
        )

    def check_password(self, password):
        return check_password_hash(
            self.password_hash,
            password
        )


class Investigation(db.Model):

    __tablename__ = "investigations"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    sender = db.Column(db.String(255))

    recipient = db.Column(db.String(255))

    subject = db.Column(db.String(255))

    risk_score = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    risk_level = db.Column(
        db.String(20),
        nullable=False,
        default="Low"
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="New"
    )

    analyst_notes = db.Column(db.Text, nullable=True)

    analysis_results = db.Column(db.JSON, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return f"<Investigation {self.id}: {self.subject}>"
