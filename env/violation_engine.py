"""Advanced violation engine with dynamic injection, mutation, and difficulty scaling."""
import random
import hashlib
from typing import Any, Dict, List, Optional


class ViolationTemplate:
    """Defines a violation type with full metadata for grading."""

    def __init__(
        self,
        violation_type: str,
        data_type: str,
        description: str,
        severity: str,
        article_reference: str,
        file: str,
        line: int,
        evidence_snippet: str = "",
        recommended_fix: str = "",
        dpdp_section: str = "",
        ccpa_section: str = "",
    ):
        self.violation_type = violation_type
        self.data_type = data_type
        self.description = description
        self.severity = severity
        self.article_reference = article_reference
        self.file = file
        self.line = line
        self.evidence_snippet = evidence_snippet
        self.recommended_fix = recommended_fix
        self.dpdp_section = dpdp_section
        self.ccpa_section = ccpa_section

    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_type": self.violation_type,
            "data_type": self.data_type,
            "description": self.description,
            "severity": self.severity,
            "article_reference": self.article_reference,
            "file": self.file,
            "line": self.line,
            "evidence_snippet": self.evidence_snippet,
            "recommended_fix": self.recommended_fix,
            "dpdp_section": self.dpdp_section,
            "ccpa_section": self.ccpa_section,
        }


ALL_VIOLATION_TEMPLATES: List[ViolationTemplate] = [
    ViolationTemplate(
        violation_type="pii_logged",
        data_type="email, phone, name",
        description="User PII (name, email, phone) logged in logger.info during signup flow",
        severity="high",
        article_reference="GDPR Art. 5",
        file="routes/user.py",
        line=155,
        evidence_snippet="logger.info(f'New user signup: name={name}, email={email}, phone={phone}')",
        recommended_fix="Remove PII from log statements. Use user_id only for audit trails.",
        dpdp_section="DPDP Act Sec. 4",
        ccpa_section="CCPA Sec. 1798.100",
    ),
    ViolationTemplate(
        violation_type="pii_logged",
        data_type="email",
        description="User email and IP address logged during failed login attempts",
        severity="medium",
        article_reference="GDPR Art. 5",
        file="routes/user.py",
        line=203,
        evidence_snippet="logger.warning(f'Failed login attempt for non-existent email: {email}')",
        recommended_fix="Log only anonymized identifiers. Do not log email on failed attempts.",
        dpdp_section="DPDP Act Sec. 4",
        ccpa_section="CCPA Sec. 1798.100",
    ),
    ViolationTemplate(
        violation_type="pii_logged",
        data_type="email, user_id",
        description="User email logged during successful login with IP address",
        severity="medium",
        article_reference="GDPR Art. 5",
        file="routes/user.py",
        line=233,
        evidence_snippet="logger.info(f'User logged in successfully: email={email}, user_id={user.id}')",
        recommended_fix="Replace email logging with user_id only.",
        dpdp_section="DPDP Act Sec. 4",
    ),
    ViolationTemplate(
        violation_type="pii_returned",
        data_type="password_hash, pan_card, aadhaar_last4",
        description="Full user dict including password_hash, pan_card, and aadhaar_last4 returned in signup API response via to_dict()",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/user.py",
        line=185,
        evidence_snippet="user.to_dict() returns password_hash, pan_card, aadhaar_last4",
        recommended_fix="Use to_safe_dict() for API responses. Exclude password_hash and financial identifiers.",
        dpdp_section="DPDP Act Sec. 8",
        ccpa_section="CCPA Sec. 1798.100",
    ),
    ViolationTemplate(
        violation_type="pii_returned",
        data_type="password_hash, pan_card, aadhaar_last4",
        description="Full user dict returned in login API response exposing password_hash and PAN",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/user.py",
        line=245,
        evidence_snippet="user.to_dict() in login response includes password_hash and pan_card",
        recommended_fix="Use to_safe_dict() method that excludes sensitive fields.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="pii_returned",
        data_type="password_hash, pan_card",
        description="Full user dict including password_hash returned in profile GET API response",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/user.py",
        line=258,
        evidence_snippet="user.to_dict() in profile endpoint returns all fields including password_hash",
        recommended_fix="Replace to_dict() with to_safe_dict() in profile endpoint.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="pii_returned",
        data_type="card_number, pan_number, card_cvv_hash",
        description="Full payment dict including card_number, pan_number returned in payment confirm API response",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/payment.py",
        line=155,
        evidence_snippet="payment.to_dict() returns full card_number and pan_number",
        recommended_fix="Use to_safe_dict() which masks card_number and pan_number.",
        dpdp_section="DPDP Act Sec. 8",
        ccpa_section="CCPA Sec. 1798.81.5",
    ),
    ViolationTemplate(
        violation_type="pii_returned",
        data_type="card_number, pan_number",
        description="Full payment dict returned in payment initiate response",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/payment.py",
        line=120,
        evidence_snippet="payment.to_dict() in initiate response",
        recommended_fix="Use to_safe_dict() for payment responses.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="pii_logged",
        data_type="email, card_number, pan_number, upi_id",
        description="Card number, PAN, and UPI ID logged in plaintext during payment initiation",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/payment.py",
        line=95,
        evidence_snippet="logger.info(f'Payment initiated: ... card_number={card_number}, pan={pan_number}')",
        recommended_fix="Log only masked values using mask_card_number() and mask_pan() helpers.",
        dpdp_section="DPDP Act Sec. 8",
        ccpa_section="CCPA Sec. 1798.81.5",
    ),
    ViolationTemplate(
        violation_type="pii_logged",
        data_type="card_number, pan_number, email",
        description="Card number and PAN logged during payment confirmation with user email",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="routes/payment.py",
        line=148,
        evidence_snippet="logger.info(f'Payment confirmed: ... card={payment.card_number}, pan={payment.pan_number}')",
        recommended_fix="Use masked card and PAN in log statements.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email, name, phone",
        description="User PII (email, name, phone) sent to Mixpanel analytics without explicit consent during signup",
        severity="high",
        article_reference="GDPR Art. 6",
        file="routes/user.py",
        line=165,
        evidence_snippet="tracker.track_signup(user.id, email, name, phone)",
        recommended_fix="Check UserConsent.ANALYTICS consent before tracking. Implement opt-in mechanism.",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email",
        description="User email sent to Mixpanel during login without verifying analytics consent",
        severity="medium",
        article_reference="GDPR Art. 6",
        file="routes/user.py",
        line=238,
        evidence_snippet="tracker.track_login(user.id, email)",
        recommended_fix="Verify consent before sending to third-party analytics.",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email, amount",
        description="User email and purchase amount sent to Mixpanel without consent verification",
        severity="high",
        article_reference="GDPR Art. 6",
        file="routes/payment.py",
        line=158,
        evidence_snippet="tracker.track_purchase(user.id, order.id, payment.amount, user.email)",
        recommended_fix="Check UserConsent.ANALYTICS before tracking purchase events.",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email, name, phone",
        description="Mixpanel tracker logs full PII in analytics.py track methods with JSON serialization",
        severity="medium",
        article_reference="GDPR Art. 25",
        file="analytics.py",
        line=35,
        evidence_snippet="logger.info(f'Mixpanel event tracked: properties={json.dumps(properties)}')",
        recommended_fix="Hash or anonymize PII before logging analytics events.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email, phone, name",
        description="Google Analytics 4 tracker sends user email and phone in event params",
        severity="high",
        article_reference="GDPR Art. 6",
        file="analytics.py",
        line=130,
        evidence_snippet="'user_email': user_properties.get('email', ''), 'user_phone': user_properties.get('phone', '')",
        recommended_fix="Do not send PII to GA4. Use hashed or anonymized identifiers.",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="unauthorized_third_party",
        data_type="email, phone, name",
        description="Facebook Pixel tracker sends raw email, phone, and name in user_data",
        severity="high",
        article_reference="GDPR Art. 6",
        file="analytics.py",
        line=155,
        evidence_snippet="'em': user_data.get('email', ''), 'ph': user_data.get('phone', '')",
        recommended_fix="Hash PII values before sending to Facebook Pixel per their Advanced Matching guidelines.",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="missing_data_deletion",
        data_type="all PII",
        description="Delete account only sets is_deleted flag (soft delete). All PII including email, phone, PAN, card data retained in database. Violates GDPR Art. 17 Right to Erasure.",
        severity="high",
        article_reference="GDPR Art. 17",
        file="routes/user.py",
        line=370,
        evidence_snippet="user.is_deleted = True  # No actual data deletion occurs",
        recommended_fix="Implement hard delete or full PII anonymization. CASCADE delete related records.",
        dpdp_section="DPDP Act Sec. 12",
        ccpa_section="CCPA Sec. 1798.105",
    ),
    ViolationTemplate(
        violation_type="missing_data_deletion",
        data_type="all PII",
        description="User model retains all PII after soft delete. Orders, payments, and consent records still linked to deleted user.",
        severity="high",
        article_reference="GDPR Art. 17",
        file="models.py",
        line=20,
        evidence_snippet="is_deleted = db.Column(db.Boolean, default=False)  # Soft delete only",
        recommended_fix="Implement anonymization pipeline that replaces PII with random values on deletion.",
        dpdp_section="DPDP Act Sec. 12",
    ),
    ViolationTemplate(
        violation_type="missing_data_deletion",
        data_type="card_number, pan_number",
        description="Payment records with full card numbers and PAN retained even after associated user soft-deletes their account.",
        severity="critical",
        article_reference="GDPR Art. 17",
        file="models.py",
        line=180,
        evidence_snippet="Payment model has no cascade delete on user deletion",
        recommended_fix="Implement CASCADE DELETE or anonymize payment PII when user requests deletion.",
        dpdp_section="DPDP Act Sec. 12",
    ),
    ViolationTemplate(
        violation_type="missing_privacy_notice",
        data_type="all PII",
        description="No privacy policy link, consent checkbox, or data processing disclosure in signup endpoint. No mention of data retention period.",
        severity="medium",
        article_reference="GDPR Art. 13",
        file="routes/user.py",
        line=85,
        evidence_snippet="No privacy_policy_url or consent_required in signup flow",
        recommended_fix="Add privacy policy link and explicit consent checkbox before data collection.",
        dpdp_section="DPDP Act Sec. 5",
    ),
    ViolationTemplate(
        violation_type="unencrypted_storage",
        data_type="phone, pan_card, aadhaar_last4",
        description="Phone number, PAN card, and Aadhaar last 4 stored as plaintext VARCHAR in users table without encryption.",
        severity="medium",
        article_reference="GDPR Art. 32",
        file="schema.sql",
        line=6,
        evidence_snippet="phone VARCHAR(15) NOT NULL, pan_card VARCHAR(10)",
        recommended_fix="Encrypt sensitive fields at rest using AES-256. Use separate encryption key management.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="unencrypted_storage",
        data_type="card_number, pan_number, ifsc_code",
        description="Card number, PAN number, and IFSC code stored as plaintext in payments table without encryption at rest.",
        severity="critical",
        article_reference="GDPR Art. 32",
        file="schema.sql",
        line=60,
        evidence_snippet="card_number VARCHAR(16), pan_number VARCHAR(10), ifsc_code VARCHAR(11)",
        recommended_fix="Encrypt PCI-DSS sensitive fields. Card numbers must never be stored in plaintext.",
        dpdp_section="DPDP Act Sec. 8",
        ccpa_section="CCPA Sec. 1798.81.5",
    ),
    ViolationTemplate(
        violation_type="weak_password_hashing",
        data_type="password",
        description="Password hashed with SHA-256 which is not suitable for password storage. Should use bcrypt or argon2 with salt.",
        severity="high",
        article_reference="GDPR Art. 32",
        file="routes/user.py",
        line=145,
        evidence_snippet="password_hash = hashlib.sha256(password.encode()).hexdigest()",
        recommended_fix="Use bcrypt with automatic salt rounds or argon2id for password hashing.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="weak_password_hashing",
        data_type="password",
        description="SHA-256 password hashing used throughout codebase without salt. Vulnerable to rainbow table attacks.",
        severity="high",
        article_reference="GDPR Art. 32",
        file="models.py",
        line=55,
        evidence_snippet="hashlib.sha256(password.encode()).hexdigest()  # No salt used",
        recommended_fix="Implement bcrypt with per-user salt and configurable work factor.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="excessive_data_collection",
        data_type="aadhaar_last4, date_of_birth, referral_code",
        description="Collection of Aadhaar last 4, date of birth, and referral code without clear purpose specification or consent.",
        severity="medium",
        article_reference="GDPR Art. 5",
        file="models.py",
        line=20,
        evidence_snippet="aadhaar_last4 = db.Column(db.String(4)), date_of_birth = db.Column(db.Date)",
        recommended_fix="Document purpose for each data field. Implement data minimization per GDPR Art. 5(1)(c).",
        dpdp_section="DPDP Act Sec. 6",
    ),
    ViolationTemplate(
        violation_type="missing_access_control",
        data_type="all PII",
        description="Admin endpoint /export-user-data returns full PII including password_hash and card numbers without additional verification.",
        severity="high",
        article_reference="GDPR Art. 25",
        file="routes/admin.py",
        line=120,
        evidence_snippet="admin_bp.route('/export-user-data/<int:user_id>') returns user.to_dict() with all fields",
        recommended_fix="Implement additional MFA for admin data export. Mask sensitive fields in export.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="pii_in_url_params",
        data_type="user_id",
        description="User ID passed as URL query parameter in profile endpoint, visible in server logs and browser history.",
        severity="low",
        article_reference="GDPR Art. 25",
        file="routes/user.py",
        line=252,
        evidence_snippet="request.args.get('user_id') in profile GET endpoint",
        recommended_fix="Use path parameters or request body instead of query parameters for user identifiers.",
        dpdp_section="DPDP Act Sec. 8",
    ),
    ViolationTemplate(
        violation_type="missing_rate_limiting",
        data_type="all PII",
        description="Profile GET and data export endpoints lack rate limiting, enabling enumeration attacks.",
        severity="medium",
        article_reference="GDPR Art. 32",
        file="routes/user.py",
        line=252,
        evidence_snippet="@user_bp.route('/profile', methods=['GET']) has no @limiter decorator",
        recommended_fix="Add rate limiting to all endpoints that return PII.",
        dpdp_section="DPDP Act Sec. 8",
    ),
]


class ViolationEngine:
    """Generates randomized violation sets for each audit episode with difficulty scaling."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.active_violations: List[ViolationTemplate] = []
        self.episode_hash: str = ""

    def generate(
        self,
        min_violations: int = 10,
        max_violations: int = 20,
        difficulty: str = "medium",
    ) -> List[ViolationTemplate]:
        """Generate a randomized set of violations for this episode.

        Args:
            min_violations: Minimum number of violations to inject.
            max_violations: Maximum number of violations to inject.
            difficulty: Difficulty level affecting violation count and subtlety.
                'easy': 10-14 violations, obvious patterns.
                'medium': 12-18 violations, mixed patterns.
                'hard': 15-22 violations, subtle and overlapping.
        """
        difficulty_config = {
            "easy": (10, 14),
            "medium": (12, 18),
            "hard": (15, min(22, len(ALL_VIOLATION_TEMPLATES))),
        }
        min_v, max_v = difficulty_config.get(difficulty, (min_violations, max_violations))
        num_violations = self.rng.randint(min_v, min(max_v, len(ALL_VIOLATION_TEMPLATES)))

        selected = self.rng.sample(ALL_VIOLATION_TEMPLATES, num_violations)
        self.active_violations = sorted(selected, key=lambda v: (v.file, v.line))

        episode_data = f"{difficulty}:{num_violations}:{[v.file for v in self.active_violations]}"
        self.episode_hash = hashlib.md5(episode_data.encode()).hexdigest()[:8]

        return self.active_violations

    def get_ground_truth(self) -> List[Dict[str, Any]]:
        """Return ground truth violations for deterministic grading."""
        return [v.to_dict() for v in self.active_violations]

    def get_all_templates(self) -> List[Dict[str, Any]]:
        """Return all possible violation templates for reference."""
        return [v.to_dict() for v in ALL_VIOLATION_TEMPLATES]

    def get_violations_by_type(self, violation_type: str) -> List[Dict[str, Any]]:
        """Get active violations filtered by type."""
        return [v.to_dict() for v in self.active_violations if v.violation_type == violation_type]

    def get_violations_by_file(self, filename: str) -> List[Dict[str, Any]]:
        """Get active violations filtered by file."""
        return [v.to_dict() for v in self.active_violations if v.file == filename]

    def get_violations_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get active violations filtered by severity level."""
        return [v.to_dict() for v in self.active_violations if v.severity == severity]

    def get_episode_info(self) -> Dict[str, Any]:
        """Return metadata about the current episode."""
        return {
            "episode_hash": self.episode_hash,
            "total_violations": len(self.active_violations),
            "severity_breakdown": {
                "critical": len(self.get_violations_by_severity("critical")),
                "high": len(self.get_violations_by_severity("high")),
                "medium": len(self.get_violations_by_severity("medium")),
                "low": len(self.get_violations_by_severity("low")),
            },
            "type_breakdown": {
                "pii_logged": len(self.get_violations_by_type("pii_logged")),
                "pii_returned": len(self.get_violations_by_type("pii_returned")),
                "unauthorized_third_party": len(self.get_violations_by_type("unauthorized_third_party")),
                "missing_data_deletion": len(self.get_violations_by_type("missing_data_deletion")),
                "missing_privacy_notice": len(self.get_violations_by_type("missing_privacy_notice")),
                "unencrypted_storage": len(self.get_violations_by_type("unencrypted_storage")),
                "weak_password_hashing": len(self.get_violations_by_type("weak_password_hashing")),
                "excessive_data_collection": len(self.get_violations_by_type("excessive_data_collection")),
                "missing_access_control": len(self.get_violations_by_type("missing_access_control")),
                "pii_in_url_params": len(self.get_violations_by_type("pii_in_url_params")),
                "missing_rate_limiting": len(self.get_violations_by_type("missing_rate_limiting")),
            },
        }
