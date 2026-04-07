"""Admin routes for ShopEase - User management, analytics dashboard, and system config."""
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify, g
from app import db
from models import User, Order, Payment, AuditLog, SupportTicket, UserRole

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    """Decorator to require admin role."""

    @wraps(f)
    def decorated(*args, **kwargs):
        user = g.get("current_user")
        if not user or user.role != UserRole.ADMIN:
            logger.warning(f"Unauthorized admin access attempt by user_id={user.id if user else 'unknown'}")
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


@admin_bp.route("/dashboard", methods=["GET"])
@admin_required
def dashboard():
    """Get admin dashboard metrics."""
    total_users = User.query.filter_by(is_deleted=False).count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.amount)).filter(
        Order.status == "completed"
    ).scalar() or 0
    pending_tickets = SupportTicket.query.filter_by(status="open").count()

    return jsonify({
        "total_users": total_users,
        "total_orders": total_orders,
        "total_revenue": float(total_revenue),
        "pending_support_tickets": pending_tickets,
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users():
    """List all users with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "")

    query = User.query.filter_by(is_deleted=False)

    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
                User.phone.ilike(f"%{search}%"),
            )
        )

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "users": [u.to_dict() for u in pagination.items],
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
        "pages": pagination.pages,
    }), 200


@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_user(user_id):
    """Get detailed user information including all PII."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    orders = Order.query.filter_by(user_id=user_id).all()
    payments = Payment.query.join(Order).filter(Order.user_id == user_id).all()

    return jsonify({
        "user": user.to_dict(),
        "orders": [o.to_dict() for o in orders],
        "payments": [p.to_dict() for p in payments],
    }), 200


@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def get_audit_logs():
    """Retrieve audit logs for compliance review."""
    user_id = request.args.get("user_id", type=int)
    entity_type = request.args.get("entity_type", "")
    action = request.args.get("action", "")
    days = request.args.get("days", 30, type=int)

    query = AuditLog.query.filter(
        AuditLog.created_at >= datetime.utcnow() - timedelta(days=days)
    )

    if user_id:
        query = query.filter_by(user_id=user_id)
    if entity_type:
        query = query.filter_by(entity_type=entity_type)
    if action:
        query = query.filter_by(action=action)

    logs = query.order_by(AuditLog.created_at.desc()).limit(100).all()

    return jsonify({
        "audit_logs": [log.to_dict() for log in logs],
        "total_count": len(logs),
    }), 200


@admin_bp.route("/export-user-data/<int:user_id>", methods=["POST"])
@admin_required
def export_user_data(user_id):
    """Export all user data for GDPR Art. 15 / DPDP Act Sec. 5 compliance."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    orders = Order.query.filter_by(user_id=user_id).all()
    payments = Payment.query.join(Order).filter(Order.user_id == user_id).all()
    consents = user.consents.all()
    audit_logs = AuditLog.query.filter_by(user_id=user_id).all()

    export_data = {
        "user": user.to_dict(),
        "orders": [o.to_dict() for o in orders],
        "payments": [p.to_dict() for p in payments],
        "consents": [c.to_dict() for c in consents],
        "audit_logs": [a.to_dict() for a in audit_logs],
        "export_generated_at": datetime.utcnow().isoformat(),
    }

    logger.info(f"Admin data export for user_id={user_id} by admin_id={g.current_user.id}")

    return jsonify({
        "message": "User data exported successfully",
        "data": export_data,
    }), 200
