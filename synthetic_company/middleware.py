"""Middleware module for request logging and security headers."""
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware:
    """WSGI middleware that logs every incoming request with timing information."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        start_time = time.time()
        method = environ.get("REQUEST_METHOD", "UNKNOWN")
        path = environ.get("PATH_INFO", "/")
        client_ip = environ.get("REMOTE_ADDR", "unknown")
        user_agent = environ.get("HTTP_USER_AGENT", "unknown")

        logger.info(
            f"Request started: {method} {path} from {client_ip} "
            f"UA={user_agent}"
        )

        def custom_start_response(status, headers, exc_info=None):
            elapsed = time.time() - start_time
            status_code = status.split()[0]
            logger.info(
                f"Request completed: {method} {path} "
                f"status={status_code} duration={elapsed:.4f}s"
            )
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)


class SecurityHeadersMiddleware:
    """WSGI middleware that adds security headers to every response."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            security_headers = [
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("X-XSS-Protection", "1; mode=block"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Cache-Control", "no-store, no-cache, must-revalidate"),
                ("Pragma", "no-cache"),
            ]
            headers.extend(security_headers)
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)
