
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# Database extension
db = SQLAlchemy()


# User authentication extension
login_manager = LoginManager()


# CSRF protection
csrf = CSRFProtect()


# Login rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://"
)
