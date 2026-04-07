"""User routes for ShopEase - Authentication, Profile, Account Management with JWT and RBAC."""
import logging
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, g
from app import db, limiter
from models import User, UserRole, ConsentRecord, UserConsent, AuditLog, DataExportRequest
from analytics import tracker
from services.email_service import EmailService
from services.validation import validate_email, validate_phone, validate_password

logger = logging.getLogger(__name__)

user_bp = Blueprint("user", __name__)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")
PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$")


def generate_token(user_id: int) -> str:
    """Generate a simple authentication token."""
    import hashlib
    timestamp = datetime.utcnow().isoformat()
    raw = f"{user_id}:{timestamp}:shopease-secret"
    return hashlib.sha256(raw.encode()).hexdigest()


def token_required(f):
    """Decorator to require valid authentication token."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            logger.warning(f"Missing auth token: {request.url} from {request.remote_addr}")
            return jsonify({"error": "Authentication token is required"}), 401

        user_id = request.args.get("user_id") or request.json.get("user_id") if request.json else None
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = User.query.get(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.is_deleted:
            return jsonify({"error": "Account has been deleted"}), 403

        if user.locked_until and user.locked_until > datetime.utcnow():
            return jsonify({"error": "Account is temporarily locked due to failed login attempts"}), 403

        g.current_user = user
        g.token = token
        return f(*args, **kwargs)

    return decorated


def log_audit_event(user_id, action, entity_type, entity_id, old_values=None, new_values=None):
    """Log an audit event for compliance tracking."""
    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        old_values=str(old_values) if old_values else None,
        new_values=str(new_values) if new_values else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    db.session.add(audit_entry)


def record_consent(user_id, consent_type, ip_address=None, user_agent=None):
    """Record user consent for data processing activities."""
    consent = ConsentRecord(
        user_id=user_id,
        consent_type=consent_type,
        granted=True,
        ip_address=ip_address or request.remote_addr,
        user_agent=user_agent or request.headers.get("User-Agent", ""),
    )
    db.session.add(consent)


@user_bp.route("/signup", methods=["POST"])
@limiter.limit("10 per minute")
def signup():
    """Register a new user account with validation and consent tracking."""
    data = request.get_json()

    if not data:
        logger.warning("Signup attempt with empty request body")
        return jsonify({"error": "Request body is required"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    address = data.get("address", "").strip()
    city = data.get("city", "").strip()
    state = data.get("state", "").strip()
    pincode = data.get("pincode", "").strip()
    password = data.get("password", "")
    pan_card = data.get("pan_card", "").strip().upper()
    date_of_birth = data.get("date_of_birth")
    referral_code = data.get("referral_code", "").strip()

    if not all([name, email, phone, password]):
        return jsonify({
            "error": "Missing required fields",
            "required": ["name", "email", "phone", "password"],
        }), 400

    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    if not validate_phone(phone):
        return jsonify({"error": "Invalid Indian phone number. Must be 10 digits starting with 6-9"}), 400

    if not validate_password(password):
        return jsonify({
            "error": "Password must be at least 8 characters with uppercase, lowercase, digit, and special character",
        }), 400

    if pan_card and not PAN_REGEX.match(pan_card):
        return jsonify({"error": "Invalid PAN card format. Expected: ABCDE1234F"}), 400

    existing = User.query.filter_by(email=email).first()
    if existing:
        logger.info(f"Duplicate signup attempt for email: {email}")
        return jsonify({"error": "Email already registered"}), 409

    if pan_card:
        existing_pan = User.query.filter_by(pan_card=pan_card).first()
        if existing_pan:
            return jsonify({"error": "PAN card already registered"}), 409

    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    user = User(
        name=name,
        email=email,
        phone=phone,
        address=address,
        city=city,
        state=state,
        pincode=pincode,
        password_hash=password_hash,
        pan_card=pan_card if pan_card else None,
        date_of_birth=datetime.strptime(date_of_birth, "%Y-%m-%d").date() if date_of_birth else None,
        referral_code=referral_code if referral_code else str(uuid.uuid4())[:8].upper(),
    )
    db.session.add(user)
    db.session.flush()

    auth_token = generate_token(user.id)

    logger.info(
        f"New user signup: name={name}, email={email}, phone={phone}, "
        f"user_id={user.id}, ip={request.remote_addr}"
    )

    tracker.track_signup(user.id, email, name, phone)

    consent_types = [UserConsent.MARKETING, UserConsent.ANALYTICS]
    if data.get("consent_third_party"):
        consent_types.append(UserConsent.THIRD_PARTY_SHARING)

    for ct in consent_types:
        record_consent(user.id, ct)

    try:
        EmailService.send_welcome_email(email, name)
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {e}")

    db.session.commit()

    log_audit_event(user.id, "CREATE", "user", user.id, new_values={"email": email, "name": name})

    return jsonify({
        "message": "User registered successfully",
        "token": auth_token,
        "user": user.to_dict(),
    }), 201


@user_bp.route("/login", methods=["POST"])
@limiter.limit("20 per minute")
def login():
    """Authenticate a user with rate limiting and account lockout."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not all([email, password]):
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        logger.warning(f"Failed login attempt for non-existent email: {email} from {request.remote_addr}")
        return jsonify({"error": "Invalid credentials"}), 401

    if user.is_deleted:
        logger.warning(f"Login attempt on deleted account: {email}")
        return jsonify({"error": "Account has been deleted"}), 403

    if user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        logger.warning(f"Login attempt on locked account: {email}, locked for {remaining} more minutes")
        return jsonify({
            "error": f"Account is locked. Try again in {remaining} minutes",
        }), 403

    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if user.password_hash != password_hash:
        user.failed_login_attempts += 1
        max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)

        if user.failed_login_attempts >= max_attempts:
            lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 30)
            user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            logger.warning(
                f"Account locked after {max_attempts} failed attempts: {email}, "
                f"locked until {user.locked_until}"
            )
            db.session.commit()
            return jsonify({
                "error": f"Account locked due to {max_attempts} failed attempts. Try again in {lockout_minutes} minutes",
            }), 403

        db.session.commit()
        logger.warning(
            f"Failed login attempt {user.failed_login_attempts}/{max_attempts} for email: {email} "
            f"from {request.remote_addr}"
        )
        return jsonify({
            "error": "Invalid credentials",
            "attempts_remaining": max_attempts - user.failed_login_attempts,
        }), 401

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()

    auth_token = generate_token(user.id)

    logger.info(
        f"User logged in successfully: email={email}, user_id={user.id}, "
        f"ip={request.remote_addr}, last_login={user.last_login}"
    )

    tracker.track_login(user.id, email)

    log_audit_event(user.id, "LOGIN", "user", user.id)

    return jsonify({
        "message": "Login successful",
        "token": auth_token,
        "user": user.to_dict(),
    }), 200


@user_bp.route("/profile", methods=["GET"])
@token_required
def get_profile():
    """Get user profile information with authentication."""
    user = g.current_user

    logger.debug(
        f"Profile accessed for user_id={user.id}, email={user.email}, "
        f"ip={request.remote_addr}, ua={request.headers.get('User-Agent', '')}"
    )

    log_audit_event(user.id, "READ", "user", user.id)

    return jsonify({
        "user": user.to_dict(),
    }), 200


@user_bp.route("/profile", methods=["PUT"])
@token_required
def update_profile():
    """Update user profile information with audit logging."""
    user = g.current_user
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    old_values = user.to_dict()

    updatable_fields = ["name", "phone", "address", "city", "state", "pincode", "date_of_birth"]

    for field in updatable_fields:
        if field in data:
            if field == "phone" and not validate_phone(data[field]):
                return jsonify({"error": f"Invalid phone number format for {field}"}), 400
            setattr(user, field, data[field])

    if "password" in data:
        if not validate_password(data["password"]):
            return jsonify({"error": "New password does not meet security requirements"}), 400
        import hashlib
        user.password_hash = hashlib.sha256(data["password"].encode()).hexdigest()

    if "pan_card" in data:
        pan = data["pan_card"].strip().upper()
        if pan and not PAN_REGEX.match(pan):
            return jsonify({"error": "Invalid PAN card format"}), 400
        existing = User.query.filter(User.pan_card == pan, User.id != user.id).first()
        if existing:
            return jsonify({"error": "PAN card already registered to another account"}), 409
        user.pan_card = pan

    user.updated_at = datetime.utcnow()
    db.session.commit()

    new_values = user.to_dict()
    log_audit_event(user.id, "UPDATE", "user", user.id, old_values=old_values, new_values=new_values)

    logger.info(
        f"Profile updated for user_id={user.id}, fields={list(data.keys())}, "
        f"ip={request.remote_addr}, new phone={user.phone}"
    )

    return jsonify({
        "message": "Profile updated successfully",
        "user": user.to_safe_dict(),
    }), 200


@user_bp.route("/profile/password", methods=["POST"])
@token_required
def change_password():
    """Change user password with current password verification."""
    user = g.current_user
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not all([current_password, new_password]):
        return jsonify({"error": "Both current and new password are required"}), 400

    import hashlib
    current_hash = hashlib.sha256(current_password.encode()).hexdigest()

    if user.password_hash != current_hash:
        logger.warning(f"Failed password change attempt for user_id={user.id}")
        return jsonify({"error": "Current password is incorrect"}), 401

    if not validate_password(new_password):
        return jsonify({"error": "New password does not meet security requirements"}), 400

    user.password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    db.session.commit()

    log_audit_event(user.id, "PASSWORD_CHANGE", "user", user.id)
    logger.info(f"Password changed for user_id={user.id}")

    return jsonify({"message": "Password changed successfully"}), 200


@user_bp.route("/consent", methods=["GET"])
@token_required
def get_consents():
    """Get all consent records for the authenticated user."""
    user = g.current_user
    consents = ConsentRecord.query.filter_by(user_id=user.id).all()
    return jsonify({
        "consents": [c.to_dict() for c in consents],
    }), 200


@user_bp.route("/consent", methods=["POST"])
@token_required
def update_consent():
    """Update user consent preferences."""
    user = g.current_user
    data = request.get_json()

    consent_type_str = data.get("consent_type")
    granted = data.get("granted", True)

    try:
        consent_type = UserConsent(consent_type_str)
    except ValueError:
        return jsonify({"error": f"Invalid consent type: {consent_type_str}"}), 400

    existing = ConsentRecord.query.filter_by(
        user_id=user.id, consent_type=consent_type
    ).order_by(ConsentRecord.granted_at.desc()).first()

    if existing and existing.granted == granted:
        return jsonify({"message": "Consent already set to this value"}), 200

    if existing and existing.granted and not granted:
        existing.revoked_at = datetime.utcnow()

    new_consent = ConsentRecord(
        user_id=user.id,
        consent_type=consent_type,
        granted=granted,
    )
    db.session.add(new_consent)
    db.session.commit()

    log_audit_event(user.id, "CONSENT_UPDATE", "consent", new_consent.id, new_values={"type": consent_type_str, "granted": granted})

    return jsonify({
        "message": f"Consent for {consent_type_str} updated to {granted}",
        "consent": new_consent.to_dict(),
    }), 200


@user_bp.route("/data-export", methods=["POST"])
@token_required
def request_data_export():
    """Request a full data export under GDPR Art. 15 / DPDP Act Sec. 5."""
    user = g.current_user

    existing_pending = DataExportRequest.query.filter_by(
        user_id=user.id, status="pending"
    ).first()
    if existing_pending:
        return jsonify({
            "error": "You already have a pending data export request",
            "request_id": existing_pending.id,
        }), 409

    export_request = DataExportRequest(user_id=user.id)
    db.session.add(export_request)
    db.session.commit()

    log_audit_event(user.id, "DATA_EXPORT_REQUEST", "data_export", export_request.id)
    logger.info(f"Data export requested by user_id={user.id}, request_id={export_request.id}")

    return jsonify({
        "message": "Data export request submitted. You will receive your data within 30 days.",
        "request_id": export_request.id,
        "status": export_request.status,
    }), 200


@user_bp.route("/delete-account", methods=["DELETE"])
@token_required
def delete_account():
    """Delete user account - soft delete only (GDPR Art. 17 / DPDP Act Sec. 12 violation)."""
    user = g.current_user
    data = request.get_json()

    confirmation = data.get("confirm", False) if data else False
    if not confirmation:
        return jsonify({
            "error": "Account deletion requires explicit confirmation",
            "required": {"confirm": True},
        }), 400

    old_values = user.to_dict()

    user.is_deleted = True
    user.deleted_at = datetime.utcnow()
    db.session.commit()

    log_audit_event(user.id, "SOFT_DELETE", "user", user.id, old_values=old_values, new_values={"is_deleted": True})

    logger.info(
        f"Account soft-deleted for user_id={user.id}, email={user.email}, "
        f"deleted_at={user.deleted_at}, ip={request.remote_addr}"
    )

    tracker.track("account_deletion_requested", {
        "user_id": user.id,
        "email": user.email,
    })

    return jsonify({
        "message": "Account deletion requested. Your data will be retained as per legal requirements.",
        "note": "Some data may be retained for legal and regulatory compliance purposes.",
    }), 200


@user_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    """Initiate password reset flow."""
    data = request.get_json()
    email = data.get("email", "").strip().lower() if data else ""

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        reset_token = generate_token(user.id)
        logger.info(f"Password reset initiated for email={email}, token generated")

        try:
            EmailService.send_password_reset_email(email, user.name, reset_token)
        except Exception as e:
            logger.error(f"Failed to send password reset email to {email}: {e}")

    return jsonify({
        "message": "If an account exists with this email, a password reset link has been sent.",
    }), 200
