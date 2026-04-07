"""Advanced database models for ShopEase India Pvt. Ltd. with comprehensive PII handling."""
import enum
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

from app import db


class UserRole(enum.Enum):
    """User role enumeration for access control."""
    CUSTOMER = "customer"
    SELLER = "seller"
    ADMIN = "admin"
    SUPPORT = "support"


class UserConsent(enum.Enum):
    """User consent tracking for GDPR/DPDP compliance."""
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    THIRD_PARTY_SHARING = "third_party_sharing"
    PERSONALIZATION = "personalization"


class User(db.Model):
    """User model with comprehensive PII fields and consent tracking."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(15), nullable=False)
    phone_verified = db.Column(db.Boolean, default=False)
    address = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(50), nullable=True)
    state = db.Column(db.String(50), nullable=True)
    pincode = db.Column(db.String(6), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    pan_card = db.Column(db.String(10), nullable=True, unique=True)
    aadhaar_last4 = db.Column(db.String(4), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    role = db.Column(db.Enum(UserRole), default=UserRole.CUSTOMER)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    referral_code = db.Column(db.String(20), nullable=True, unique=True)
    referred_by = db.Column(db.String(20), nullable=True)

    orders = db.relationship("Order", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    consents = db.relationship("ConsentRecord", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    support_tickets = db.relationship("SupportTicket", backref="user", lazy="dynamic", foreign_keys="SupportTicket.user_id")

    def set_password(self, password: str) -> None:
        """Hash and set the user password using SHA-256."""
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize user to dictionary - WARNING: includes sensitive fields."""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "phone_verified": self.phone_verified,
            "address": self.address,
            "city": self.city,
            "state": self.state,
            "pincode": self.pincode,
            "password_hash": self.password_hash,
            "pan_card": self.pan_card,
            "aadhaar_last4": self.aadhaar_last4,
            "date_of_birth": self.date_of_birth.isoformat() if self.date_of_birth else None,
            "role": self.role.value if self.role else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_deleted": self.is_deleted,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "failed_login_attempts": self.failed_login_attempts,
            "referral_code": self.referral_code,
        }

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serialize user excluding sensitive fields - safe for API responses."""
        data = self.to_dict()
        data.pop("password_hash", None)
        data.pop("pan_card", None)
        data.pop("aadhaar_last4", None)
        data.pop("failed_login_attempts", None)
        return data

    def __repr__(self) -> str:
        return f"<User {self.id}: {self.email}>"


class ConsentRecord(db.Model):
    """Track user consent for various data processing activities."""
    __tablename__ = "consent_records"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    consent_type = db.Column(db.Enum(UserConsent), nullable=False)
    granted = db.Column(db.Boolean, default=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "consent_type": self.consent_type.value,
            "granted": self.granted,
            "granted_at": self.granted_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


class Order(db.Model):
    """Order model with full audit trail."""
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    order_number = db.Column(db.String(20), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    tax_amount = db.Column(db.Float, default=0.0)
    shipping_amount = db.Column(db.Float, default=0.0)
    discount_amount = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="pending", index=True)
    shipping_address = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    delivered_at = db.Column(db.DateTime, nullable=True)

    items = db.relationship("OrderItem", backref="order", lazy=True, cascade="all, delete-orphan")
    payment = db.relationship("Payment", backref="order", uselist=False, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="order", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "order_number": self.order_number,
            "user_id": self.user_id,
            "amount": self.amount,
            "tax_amount": self.tax_amount,
            "shipping_amount": self.shipping_amount,
            "discount_amount": self.discount_amount,
            "status": self.status,
            "shipping_address": self.shipping_address,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
        }


class OrderItem(db.Model):
    """Individual items within an order."""
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    product_sku = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    unit_price = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "product_name": self.product_name,
            "product_sku": self.product_sku,
            "quantity": self.quantity,
            "unit_price": self.unit_price,
            "total_price": self.total_price,
        }


class Payment(db.Model):
    """Payment model with sensitive financial data."""
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, unique=True)
    payment_method = db.Column(db.String(20), default="card")
    card_number = db.Column(db.String(16), nullable=True)
    card_holder_name = db.Column(db.String(100), nullable=True)
    card_expiry = db.Column(db.String(5), nullable=True)
    card_cvv_hash = db.Column(db.String(64), nullable=True)
    pan_number = db.Column(db.String(10), nullable=True)
    upi_id = db.Column(db.String(50), nullable=True)
    bank_account_last4 = db.Column(db.String(4), nullable=True)
    ifsc_code = db.Column(db.String(11), nullable=True)
    transaction_id = db.Column(db.String(50), nullable=True, unique=True)
    gateway_response = db.Column(db.Text, nullable=True)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default="INR")
    status = db.Column(db.String(20), default="pending", index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    refund_amount = db.Column(db.Float, default=0.0)
    refund_reason = db.Column(db.String(500), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize payment - WARNING: includes full card number and PAN."""
        return {
            "id": self.id,
            "order_id": self.order_id,
            "payment_method": self.payment_method,
            "card_number": self.card_number,
            "card_holder_name": self.card_holder_name,
            "card_expiry": self.card_expiry,
            "pan_number": self.pan_number,
            "upi_id": self.upi_id,
            "bank_account_last4": self.bank_account_last4,
            "ifsc_code": self.ifsc_code,
            "transaction_id": self.transaction_id,
            "amount": self.amount,
            "currency": self.currency,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "refund_amount": self.refund_amount,
            "refund_reason": self.refund_reason,
        }

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serialize payment with masked sensitive fields."""
        data = self.to_dict()
        if data.get("card_number"):
            data["card_number"] = f"**** **** **** {data['card_number'][-4:]}"
        if data.get("pan_number"):
            data["pan_number"] = f"*****{data['pan_number'][-4:]}"
        if data.get("upi_id"):
            parts = data["upi_id"].split("@")
            if len(parts) == 2:
                masked_id = parts[0][:3] + "****@" + parts[1]
                data["upi_id"] = masked_id
        data.pop("card_cvv_hash", None)
        data.pop("bank_account_last4", None)
        data.pop("ifsc_code", None)
        return data


class SupportTicket(db.Model):
    """Customer support ticket with PII in descriptions."""
    __tablename__ = "support_tickets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), default="general")
    priority = db.Column(db.String(10), default="medium")
    status = db.Column(db.String(20), default="open")
    assigned_to = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    messages = db.relationship("TicketMessage", backref="ticket", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "order_id": self.order_id,
            "subject": self.subject,
            "description": self.description,
            "category": self.category,
            "priority": self.priority,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class TicketMessage(db.Model):
    """Individual messages within a support ticket."""
    __tablename__ = "ticket_messages"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_tickets.id"), nullable=False)
    sender_type = db.Column(db.String(10), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    attachments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ticket_id": self.ticket_id,
            "sender_type": self.sender_type,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
        }


class AuditLog(db.Model):
    """Audit log for tracking all data access and modifications."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(30), nullable=False)
    entity_id = db.Column(db.Integer, nullable=False)
    old_values = db.Column(db.Text, nullable=True)
    new_values = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat(),
        }


class DataExportRequest(db.Model):
    """Track user data export requests under GDPR Art. 15 / DPDP Act Sec. 5."""
    __tablename__ = "data_export_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    export_file_path = db.Column(db.String(500), nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "status": self.status,
            "requested_at": self.requested_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
