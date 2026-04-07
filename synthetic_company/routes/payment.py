"""Payment processing routes for ShopEase with card, UPI, NET banking, and wallet support."""
import logging
import re
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP

from flask import Blueprint, request, jsonify, current_app, g
from app import db, limiter
from models import Payment, Order, User, AuditLog
from analytics import tracker
from services.validation import validate_pan, validate_card_number

logger = logging.getLogger(__name__)

payment_bp = Blueprint("payment", __name__)

SUPPORTED_PAYMENT_METHODS = ["card", "upi", "netbanking", "wallet", "cod"]
CARD_NUMBER_REGEX = re.compile(r"^\d{16}$")
PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$")
UPI_ID_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+@[a-zA-Z]+$")


def mask_card_number(card_number: str) -> str:
    """Mask card number showing only last 4 digits."""
    if card_number and len(card_number) >= 4:
        return "**** **** **** " + card_number[-4:]
    return "****"


def mask_pan(pan: str) -> str:
    """Mask PAN number showing only last 4 characters."""
    if pan and len(pan) >= 4:
        return "*****" + pan[-4:]
    return "*****"


def calculate_gst(amount: float) -> float:
    """Calculate 18% GST on the payment amount."""
    return float((Decimal(str(amount)) * Decimal("0.18")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def log_payment_audit(user_id, action, payment_id, details=None):
    """Log payment-related audit events for compliance."""
    audit = AuditLog(
        user_id=user_id,
        action=action,
        entity_type="payment",
        entity_id=payment_id,
        new_values=str(details) if details else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    db.session.add(audit)


@payment_bp.route("/payment/initiate", methods=["POST"])
@limiter.limit("30 per minute")
def initiate_payment():
    """Initiate a payment with support for multiple payment methods."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    user_id = data.get("user_id")
    order_id = data.get("order_id")
    payment_method = data.get("payment_method", "card")
    amount = data.get("amount")

    if not all([user_id, order_id, amount]):
        return jsonify({
            "error": "Missing required fields",
            "required": ["user_id", "order_id", "amount"],
        }), 400

    if payment_method not in SUPPORTED_PAYMENT_METHODS:
        return jsonify({
            "error": f"Unsupported payment method: {payment_method}",
            "supported": SUPPORTED_PAYMENT_METHODS,
        }), 400

    user = User.query.get(int(user_id))
    order = Order.query.get(int(order_id))

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not order:
        return jsonify({"error": "Order not found"}), 404

    if order.user_id != user_id:
        logger.warning(
            f"Payment initiation mismatch: user_id={user_id} trying to pay for "
            f"order_id={order_id} owned by user_id={order.user_id}"
        )
        return jsonify({"error": "Order does not belong to this user"}), 403

    if order.status != "pending":
        return jsonify({"error": f"Cannot initiate payment for order with status: {order.status}"}), 400

    card_number = data.get("card_number", "").replace(" ", "").replace("-", "")
    card_holder_name = data.get("card_holder_name", "").strip()
    card_expiry = data.get("card_expiry", "").strip()
    pan_number = data.get("pan_number", "").strip().upper()
    upi_id = data.get("upi_id", "").strip().lower()
    bank_account_last4 = data.get("bank_account_last4", "").strip()
    ifsc_code = data.get("ifsc_code", "").strip().upper()

    if payment_method == "card":
        if not card_number or not card_expiry:
            return jsonify({"error": "Card number and expiry are required for card payments"}), 400
        if not CARD_NUMBER_REGEX.match(card_number):
            return jsonify({"error": "Invalid card number format"}), 400
        if not re.match(r"^\d{2}/\d{2}$", card_expiry):
            return jsonify({"error": "Invalid card expiry format. Use MM/YY"}), 400

    if payment_method == "upi":
        if not upi_id:
            return jsonify({"error": "UPI ID is required for UPI payments"}), 400
        if not UPI_ID_REGEX.match(upi_id):
            return jsonify({"error": "Invalid UPI ID format"}), 400

    if payment_method == "netbanking":
        if not ifsc_code or not bank_account_last4:
            return jsonify({"error": "IFSC code and last 4 digits of account are required"}), 400

    logger.info(
        f"Payment initiated: user_id={user_id}, email={user.email}, "
        f"order_id={order_id}, method={payment_method}, amount={amount}, "
        f"card_number={card_number}, pan={pan_number}, upi_id={upi_id}, "
        f"ip={request.remote_addr}"
    )

    payment = Payment(
        order_id=order_id,
        payment_method=payment_method,
        card_number=card_number if card_number else None,
        card_holder_name=card_holder_name if card_holder_name else None,
        card_expiry=card_expiry if card_expiry else None,
        pan_number=pan_number if pan_number else None,
        upi_id=upi_id if upi_id else None,
        bank_account_last4=bank_account_last4 if bank_account_last4 else None,
        ifsc_code=ifsc_code if ifsc_code else None,
        amount=float(amount),
        status="initiated",
    )
    db.session.add(payment)
    db.session.commit()

    log_payment_audit(user_id, "PAYMENT_INITIATED", payment.id, {
        "method": payment_method,
        "amount": amount,
        "order_id": order_id,
    })

    return jsonify({
        "message": "Payment initiated successfully",
        "payment": payment.to_dict(),
        "masked_card": mask_card_number(card_number) if card_number else None,
        "masked_pan": mask_pan(pan_number) if pan_number else None,
    }), 200


@payment_bp.route("/payment/confirm", methods=["POST"])
@limiter.limit("20 per minute")
def confirm_payment():
    """Confirm a payment and process the order."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    payment_id = data.get("payment_id")
    gateway_transaction_id = data.get("gateway_transaction_id")
    gateway_response = data.get("gateway_response")

    if not payment_id:
        return jsonify({"error": "payment_id is required"}), 400

    payment = Payment.query.get(int(payment_id))
    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    if payment.status == "confirmed":
        return jsonify({"error": "Payment is already confirmed"}), 400

    if payment.status == "failed":
        return jsonify({"error": "Cannot confirm a failed payment. Initiate a new one."}), 400

    payment.status = "confirmed"
    payment.transaction_id = gateway_transaction_id or f"TXN-{payment_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    payment.gateway_response = str(gateway_response) if gateway_response else None
    payment.processed_at = datetime.utcnow()
    db.session.commit()

    order = Order.query.get(payment.order_id)
    if order:
        order.status = "confirmed"
        order.updated_at = datetime.utcnow()
        db.session.commit()

    user = User.query.get(order.user_id)

    gst_amount = calculate_gst(payment.amount)

    logger.info(
        f"Payment confirmed: payment_id={payment_id}, order_id={order.id}, "
        f"amount={payment.amount}, gst={gst_amount}, "
        f"card={payment.card_number}, pan={payment.pan_number}, "
        f"user_id={user.id}, email={user.email}, "
        f"transaction_id={payment.transaction_id}"
    )

    tracker.track_purchase(user.id, order.id, payment.amount, user.email)

    log_payment_audit(user.id, "PAYMENT_CONFIRMED", payment.id, {
        "transaction_id": payment.transaction_id,
        "amount": payment.amount,
        "gst": gst_amount,
        "method": payment.payment_method,
    })

    return jsonify({
        "message": "Payment confirmed successfully",
        "payment": payment.to_dict(),
        "order": order.to_dict(),
        "user": user.to_dict(),
        "gst_breakdown": {
            "base_amount": payment.amount,
            "gst_18_percent": gst_amount,
            "total": payment.amount + gst_amount,
        },
    }), 200


@payment_bp.route("/payment/status", methods=["GET"])
def payment_status():
    """Check the status of a payment."""
    payment_id = request.args.get("payment_id")

    if not payment_id:
        return jsonify({"error": "payment_id is required"}), 400

    payment = Payment.query.get(int(payment_id))
    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    return jsonify({
        "payment": payment.to_safe_dict(),
    }), 200


@payment_bp.route("/payment/refund", methods=["POST"])
@limiter.limit("10 per hour")
def refund_payment():
    """Initiate a refund for a confirmed payment."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    payment_id = data.get("payment_id")
    refund_amount = data.get("refund_amount")
    reason = data.get("reason", "Customer requested refund")

    if not payment_id:
        return jsonify({"error": "payment_id is required"}), 400

    payment = Payment.query.get(int(payment_id))
    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    if payment.status != "confirmed":
        return jsonify({"error": "Only confirmed payments can be refunded"}), 400

    refund_amt = float(refund_amount) if refund_amount else payment.amount
    if refund_amt > payment.amount:
        return jsonify({"error": "Refund amount cannot exceed payment amount"}), 400

    payment.status = "refunded"
    payment.refund_amount = refund_amt
    payment.refund_reason = reason
    db.session.commit()

    order = Order.query.get(payment.order_id)
    if order:
        order.status = "refunded"
        db.session.commit()

    user = User.query.get(order.user_id) if order else None

    logger.info(
        f"Payment refunded: payment_id={payment_id}, amount={refund_amt}, "
        f"reason={reason}, user_id={user.id if user else 'unknown'}"
    )

    log_payment_audit(user.id if user else None, "PAYMENT_REFUNDED", payment.id, {
        "refund_amount": refund_amt,
        "reason": reason,
    })

    return jsonify({
        "message": "Refund processed successfully",
        "refund_amount": refund_amt,
        "payment": payment.to_safe_dict(),
    }), 200


@payment_bp.route("/payment/history", methods=["GET"])
def payment_history():
    """Get payment history for a user."""
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    payments = Payment.query.join(Order).filter(
        Order.user_id == int(user_id)
    ).order_by(Payment.created_at.desc()).all()

    return jsonify({
        "payments": [p.to_safe_dict() for p in payments],
        "total_count": len(payments),
    }), 200
