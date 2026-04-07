"""Configuration module for ShopEase India Pvt. Ltd. application."""
import os
from datetime import timedelta


class BaseConfig:
    """Base configuration shared across all environments."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max request size
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    CORS_ORIGINS = "*"
    LOG_LEVEL = "INFO"
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    PAGINATION_PER_PAGE = 20
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    PASSWORD_MIN_LENGTH = 8
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class DevelopmentConfig(BaseConfig):
    """Development-specific configuration."""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///shopease_dev.db"
    )
    LOG_LEVEL = "DEBUG"
    RATELIMIT_ENABLED = False


class ProductionConfig(BaseConfig):
    """Production-specific configuration."""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///shopease.db")
    LOG_LEVEL = "WARNING"
    RATELIMIT_ENABLED = True
    SESSION_COOKIE_SECURE = True


class TestingConfig(BaseConfig):
    """Testing-specific configuration."""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False
    WTF_CSRF_ENABLED = False


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
