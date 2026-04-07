"""Task 3: Compliance Gap Report - Hard difficulty.

Agent must generate a structured JSON compliance report auditing the codebase
against GDPR Articles 5, 6, 13, 14, 15, 16, 17, 25, 32 and India's DPDP Act
Sections 4, 5, 6, 8, 9, 12. Each finding must cite exact file, line, article,
violation description, evidence, and recommended fix.

This task requires multi-file reasoning, legal knowledge, and the ability to
connect code patterns to specific regulatory requirements.
"""

TASK_ID = "compliance_gap_report"
TASK_NAME = "Compliance Gap Report"
DIFFICULTY = "hard"
MAX_STEPS = 40
DESCRIPTION = (
    "Generate a structured JSON compliance report auditing the ShopEase codebase "
    "against GDPR Articles 5, 6, 13, 14, 15, 16, 17, 25, 32 and India's DPDP Act "
    "Sections 4, 5, 6, 8, 9, 12. Each finding must include: article reference, "
    "violation description, file location with line number, severity, code evidence, "
    "and recommended fix."
)

APPLICABLE_CLAUSES = [
    "GDPR Art. 5",
    "GDPR Art. 6",
    "GDPR Art. 13",
    "GDPR Art. 14",
    "GDPR Art. 15",
    "GDPR Art. 16",
    "GDPR Art. 17",
    "GDPR Art. 25",
    "GDPR Art. 32",
    "DPDP Act Sec. 4",
    "DPDP Act Sec. 5",
    "DPDP Act Sec. 6",
    "DPDP Act Sec. 8",
    "DPDP Act Sec. 9",
    "DPDP Act Sec. 12",
]

CLAUSE_DESCRIPTIONS = {
    "GDPR Art. 5": "Principles relating to processing of personal data - lawfulness, fairness, transparency, purpose limitation, data minimization",
    "GDPR Art. 6": "Lawfulness of processing - requires valid legal basis including explicit consent",
    "GDPR Art. 13": "Information to be provided when personal data are collected - privacy notice requirements",
    "GDPR Art. 14": "Information to be provided where personal data have not been obtained from the data subject",
    "GDPR Art. 15": "Right of access by the data subject - data portability and access",
    "GDPR Art. 16": "Right to rectification - correcting inaccurate personal data",
    "GDPR Art. 17": "Right to erasure (right to be forgotten) - complete deletion of personal data",
    "GDPR Art. 25": "Data protection by design and by default - privacy-first architecture",
    "GDPR Art. 32": "Security of processing - encryption, pseudonymization, access controls",
    "DPDP Act Sec. 4": "Notice and consent requirements before collecting personal data",
    "DPDP Act Sec. 5": "Right to access information about personal data being processed",
    "DPDP Act Sec. 6": "Processing of personal data only for legitimate and specified purposes",
    "DPDP Act Sec. 8": "Obligations of data fiduciary - security safeguards, breach notification",
    "DPDP Act Sec. 9": "Additional obligations for processing children's data",
    "DPDP Act Sec. 12": "Right to erasure of personal data when purpose is fulfilled",
}

EXPECTED_FINDINGS = [
    {
        "article": "GDPR Art. 17 / DPDP Act Sec. 12",
        "violation_type": "missing_data_deletion",
        "violation": "Right to Erasure not implemented - soft delete only",
        "location": "routes/user.py",
        "severity": "high",
        "evidence": "user.is_deleted = True  # No actual data deletion occurs",
        "recommended_fix": "Implement hard delete or full PII anonymization with CASCADE DELETE on related records",
    },
    {
        "article": "GDPR Art. 32 / DPDP Act Sec. 8",
        "violation_type": "pii_returned",
        "violation": "Sensitive PII returned in API responses without masking",
        "location": "routes/user.py",
        "severity": "critical",
        "evidence": "user.to_dict() returns password_hash, pan_card, aadhaar_last4",
        "recommended_fix": "Use to_safe_dict() method that excludes password_hash and financial identifiers from API responses",
    },
    {
        "article": "GDPR Art. 5 / DPDP Act Sec. 4",
        "violation_type": "pii_logged",
        "violation": "User PII logged in application logs in plaintext",
        "location": "routes/user.py",
        "severity": "high",
        "evidence": "logger.info(f'New user signup: name={name}, email={email}, phone={phone}')",
        "recommended_fix": "Remove PII from log statements. Use user_id only for audit trails.",
    },
    {
        "article": "GDPR Art. 6 / DPDP Act Sec. 6",
        "violation_type": "unauthorized_third_party",
        "violation": "User data shared with third-party analytics without explicit consent",
        "location": "routes/user.py",
        "severity": "high",
        "evidence": "tracker.track_signup(user.id, email, name, phone) called without consent check",
        "recommended_fix": "Implement explicit opt-in consent mechanism before sharing data with Mixpanel, GA4, Facebook Pixel",
    },
    {
        "article": "GDPR Art. 32 / DPDP Act Sec. 8",
        "violation_type": "unencrypted_storage",
        "violation": "Sensitive financial data stored in plaintext in database",
        "location": "schema.sql",
        "severity": "critical",
        "evidence": "card_number VARCHAR(16), pan_number VARCHAR(10) stored without encryption",
        "recommended_fix": "Encrypt PCI-DSS sensitive fields at rest using AES-256. Card numbers must never be stored in plaintext.",
    },
    {
        "article": "GDPR Art. 13 / DPDP Act Sec. 5",
        "violation_type": "missing_privacy_notice",
        "violation": "No privacy notice or consent mechanism at data collection",
        "location": "routes/user.py",
        "severity": "medium",
        "evidence": "No privacy policy link or consent checkbox in signup flow",
        "recommended_fix": "Add privacy policy link, explicit consent checkbox, and data retention period disclosure before data collection",
    },
    {
        "article": "GDPR Art. 32",
        "violation_type": "weak_password_hashing",
        "violation": "Password hashed with SHA-256 without salt - vulnerable to rainbow table attacks",
        "location": "routes/user.py",
        "severity": "high",
        "evidence": "hashlib.sha256(password.encode()).hexdigest() used throughout codebase",
        "recommended_fix": "Use bcrypt with automatic salt rounds or argon2id for password hashing",
    },
    {
        "article": "GDPR Art. 25 / DPDP Act Sec. 8",
        "violation_type": "missing_access_control",
        "violation": "Admin endpoint exposes full PII including password_hash and card numbers",
        "location": "routes/admin.py",
        "severity": "high",
        "evidence": "admin export endpoint returns user.to_dict() with all sensitive fields",
        "recommended_fix": "Implement MFA for admin data export. Mask sensitive fields. Add audit logging for all admin data access.",
    },
]
