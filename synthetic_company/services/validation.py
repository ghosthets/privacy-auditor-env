"""Validation utilities for ShopEase input sanitization."""
import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")
PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$")
CARD_REGEX = re.compile(r"^\d{16}$")
PASSWORD_MIN_LENGTH = 8


def validate_email(email: str) -> bool:
    """Validate email format."""
    return bool(EMAIL_REGEX.match(email))


def validate_phone(phone: str) -> bool:
    """Validate Indian phone number format."""
    return bool(PHONE_REGEX.match(phone))


def validate_password(password: str) -> bool:
    """Validate password meets minimum security requirements."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    return has_upper and has_lower and has_digit and has_special


def validate_pan(pan: str) -> bool:
    """Validate PAN card format."""
    return bool(PAN_REGEX.match(pan))


def validate_card_number(card_number: str) -> bool:
    """Validate card number format."""
    return bool(CARD_REGEX.match(card_number))
