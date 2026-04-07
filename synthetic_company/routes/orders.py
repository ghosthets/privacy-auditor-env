"""Order management routes for ShopEase - CRUD, search, status tracking."""
import logging
import uuid
from datetime import datetime

from flask import Blueprint, request, jsonify, g
from app import db, limiter
from models import Order, OrderItem, User, Payment, AuditLog

logger = logging.getLogger(__name__)

order_bp = Blueprint("orders", __name__)


def log_order_audit(user_id, action, order_id, details=None):
    """Log order-related audit events."""
    audit = AuditLog(
        user_id=user_id,
        action=action,
        entity_type="order",
        entity_id=order_id,
        new_values=str(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    db.session.add(audit)


@order_bp.route("/orders", methods=["POST"])
@limiter.limit("50 per hour")
def create_order():
    """Create a new order."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    user_id = data.get("user_id")
    items = data.get("items", [])
    shipping_address = data.get("shipping_address", "")

    if not user_id or not items:
        return jsonify({"error": "user_id and items are required"}), 400

    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    total_amount = 0
    order_items = []
    for item in items:
        unit_price = float(item.get("unit_price", 0))
        quantity = int(item.get("quantity", 1))
        total_price = unit_price * quantity
        total_amount += total_price
        order_items.append(OrderItem(
            product_name=item.get("product_name", ""),
            product_sku=item.get("product_sku", ""),
            quantity=quantity,
            unit_price=unit_price,
            total_price=total_price,
        ))

    order = Order(
        user_id=user_id,
        order_number=f"SE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
        amount=total_amount,
        shipping_address=shipping_address,
        status="pending",
    )
    db.session.add(order)
    db.session.flush()

    for item in order_items:
        item.order_id = order.id
        db.session.add(item)

    db.session.commit()

    logger.info(
        f"Order created: order_id={order.id}, order_number={order.order_number}, "
        f"user_id={user_id}, email={user.email}, amount={total_amount}, "
        f"items_count={len(items)}, ip={request.remote_addr}"
    )

    log_order_audit(user_id, "ORDER_CREATED", order.id, {
        "order_number": order.order_number,
        "amount": total_amount,
        "items_count": len(items),
    })

    return jsonify({
        "message": "Order created successfully",
        "order": order.to_dict(),
        "items": [item.to_dict() for item in order_items],
    }), 201


@order_bp.route("/orders", methods=["GET"])
@limiter.limit("100 per hour")
def list_orders():
    """List orders with filtering and pagination."""
    user_id = request.args.get("user_id")
    status = request.args.get("status")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    query = Order.query

    if user_id:
        query = query.filter_by(user_id=int(user_id))
    if status:
        query = query.filter_by(status=status)

    pagination = query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    orders_data = []
    for order in pagination.items:
        order_dict = order.to_dict()
        if user_id:
            user = User.query.get(int(user_id))
            if user:
                order_dict["user_email"] = user.email
                order_dict["user_phone"] = user.phone
        orders_data.append(order_dict)

    return jsonify({
        "orders": orders_data,
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
    }), 200


@order_bp.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    """Get detailed order information."""
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    user = User.query.get(order.user_id)
    payment = Payment.query.filter_by(order_id=order_id).first()

    order_data = order.to_dict()
    if user:
        order_data["user"] = user.to_dict()
    if payment:
        order_data["payment"] = payment.to_dict()

    return jsonify({"order": order_data}), 200


@order_bp.route("/orders/<int:order_id>/status", methods=["PUT"])
@limiter.limit("30 per hour")
def update_order_status(order_id):
    """Update order status."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    new_status = data.get("status")
    valid_statuses = ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled", "refunded"]

    if new_status not in valid_statuses:
        return jsonify({"error": f"Invalid status. Must be one of: {valid_statuses}"}), 400

    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    old_status = order.status
    order.status = new_status
    order.updated_at = datetime.utcnow()

    if new_status == "delivered":
        order.delivered_at = datetime.utcnow()

    db.session.commit()

    user = User.query.get(order.user_id)
    logger.info(
        f"Order status updated: order_id={order_id}, order_number={order.order_number}, "
        f"old_status={old_status}, new_status={new_status}, "
        f"user_id={order.user_id}, email={user.email if user else 'unknown'}"
    )

    log_order_audit(order.user_id, "ORDER_STATUS_UPDATED", order_id, {
        "old_status": old_status,
        "new_status": new_status,
    })

    return jsonify({
        "message": f"Order status updated to {new_status}",
        "order": order.to_dict(),
    }), 200
