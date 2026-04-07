"""Task 1: PII Leakage Detection - Easy difficulty.

Agent must scan the ShopEase Flask codebase and identify all locations where
user PII (email, phone, PAN card, password, card numbers) is unnecessarily
logged or returned in API responses.

The codebase contains 28+ violation templates across 11 files. The agent
must use search_pattern, read_file, and flag_violation actions to find them.
"""

TASK_ID = "pii_detection"
TASK_NAME = "PII Leakage Detection"
DIFFICULTY = "easy"
MAX_STEPS = 15
DESCRIPTION = (
    "Scan the Flask application codebase and identify all locations where "
    "user PII (email, phone, PAN card, password, card numbers) is unnecessarily "
    "logged or returned in API responses. The codebase is a realistic e-commerce "
    "backend called ShopEase India Pvt. Ltd."
)

VIOLATION_TYPES_TO_FIND = [
    "pii_logged",
    "pii_returned",
    "unauthorized_third_party",
    "missing_data_deletion",
    "missing_privacy_notice",
    "unencrypted_storage",
    "weak_password_hashing",
    "excessive_data_collection",
    "missing_access_control",
    "pii_in_url_params",
    "missing_rate_limiting",
]

HIGH_RISK_FILES = [
    "routes/user.py",
    "routes/payment.py",
    "routes/admin.py",
    "analytics.py",
    "models.py",
]

SEARCH_PATTERNS_HINT = [
    "logger.info",
    "logger.debug",
    "logger.warning",
    "to_dict()",
    "tracker.track",
    "hashlib.sha256",
    "is_deleted",
]
