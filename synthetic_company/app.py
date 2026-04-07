"""ShopEase India Pvt. Ltd. - Production-grade E-Commerce Flask Application."""
import os
import logging
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

from flask import Flask, request, jsonify, g, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from routes.user import user_bp
from routes.payment import payment_bp
from routes.admin import admin_bp
from middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware
from config import DevelopmentConfig, ProductionConfig

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_class=None):
    """Application factory pattern for creating the Flask application."""
    app = Flask(__name__)

    if config_class is None:
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(config_class)

    db.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    app.wsgi_app = RequestLoggingMiddleware(app.wsgi_app)
    app.wsgi_app = SecurityHeadersMiddleware(app.wsgi_app)

    app.register_blueprint(user_bp, url_prefix="/api")
    app.register_blueprint(payment_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    setup_logging(app)
    register_error_handlers(app)

    with app.app_context():
        db.create_all()
        seed_initial_data()

    logger.info("ShopEase India Pvt. Ltd. application initialized successfully")
    return app


def setup_logging(app):
    """Configure application-wide logging with file rotation."""
    if not app.debug and not app.testing:
        log_dir = os.path.join(app.instance_path, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "shopease.log")

        file_handler = RotatingFileHandler(
            log_file, maxBytes=10240, backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info("ShopEase startup - logging initialized")


def register_error_handlers(app):
    """Register global error handlers for the application."""

    @app.errorhandler(400)
    def bad_request(error):
        logger.warning(f"Bad request: {request.url} - {error}")
        return jsonify({"error": "Bad request", "message": str(error)}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        logger.warning(f"Unauthorized access attempt: {request.url}")
        return jsonify({"error": "Unauthorized", "message": str(error)}), 401

    @app.errorhandler(403)
    def forbidden(error):
        logger.warning(f"Forbidden access: {request.url} from {request.remote_addr}")
        return jsonify({"error": "Forbidden", "message": str(error)}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found", "message": str(error)}), 404

    @app.errorhandler(429)
    def rate_limited(error):
        logger.warning(f"Rate limit exceeded: {request.remote_addr}")
        return jsonify({"error": "Rate limited", "message": "Too many requests"}), 429

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Internal server error", "message": str(error)}), 500


def seed_initial_data():
    """Seed the database with initial test data for development."""
    from models import User, Order, Payment

    if User.query.first() is not None:
        return

    admin_user = User(
        name="Admin User",
        email="admin@shopease.in",
        phone="9876543210",
        address="ShopEase HQ, Bangalore, Karnataka",
        password_hash=hashlib.sha256("admin123".encode()).hexdigest(),
        pan_card="ABCDE1234F",
    )
    db.session.add(admin_user)
    db.session.commit()

    test_order = Order(
        user_id=admin_user.id,
        amount=2999.00,
        status="completed",
    )
    db.session.add(test_order)
    db.session.commit()

    test_payment = Payment(
        order_id=test_order.id,
        card_number="4111111111111111",
        card_expiry="12/26",
        pan_number="ABCDE1234F",
        status="completed",
    )
    db.session.add(test_payment)
    db.session.commit()

    logger.info("Initial seed data created successfully")


if __name__ == "__main__":
    application = create_app()
    port = int(os.environ.get("PORT", 5000))
    application.run(host="0.0.0.0", port=port, debug=True)
