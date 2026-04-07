"""Support ticket routes for ShopEase - Customer support with PII in descriptions."""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, g
from app import db, limiter
from models import SupportTicket, TicketMessage, User, Order, AuditLog

logger = logging.getLogger(__name__)

support_bp = Blueprint("support", __name__)


@support_bp.route("/support/tickets", methods=["POST"])
@limiter.limit("20 per hour")
def create_ticket():
    """Create a new support ticket."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    user_id = data.get("user_id")
    subject = data.get("subject", "").strip()
    description = data.get("description", "").strip()
    category = data.get("category", "general")
    priority = data.get("priority", "medium")
    order_id = data.get("order_id")

    if not all([user_id, subject, description]):
        return jsonify({"error": "user_id, subject, and description are required"}), 400

    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    ticket = SupportTicket(
        user_id=user_id,
        order_id=order_id,
        subject=subject,
        description=description,
        category=category,
        priority=priority,
    )
    db.session.add(ticket)
    db.session.commit()

    logger.info(
        f"Support ticket created: ticket_id={ticket.id}, user_id={user_id}, "
        f"email={user.email}, phone={user.phone}, subject={subject}, "
        f"description={description[:100]}, category={category}"
    )

    audit = AuditLog(
        user_id=user_id,
        action="SUPPORT_TICKET_CREATED",
        entity_type="support_ticket",
        entity_id=ticket.id,
        new_values=str({"subject": subject, "category": category, "description": description[:200]}),
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "message": "Support ticket created",
        "ticket": ticket.to_dict(),
    }), 201


@support_bp.route("/support/tickets", methods=["GET"])
def list_tickets():
    """List support tickets with filtering."""
    user_id = request.args.get("user_id")
    status = request.args.get("status")

    query = SupportTicket.query

    if user_id:
        query = query.filter_by(user_id=int(user_id))
    if status:
        query = query.filter_by(status=status)

    tickets = query.order_by(SupportTicket.created_at.desc()).all()

    tickets_data = []
    for ticket in tickets:
        ticket_dict = ticket.to_dict()
        user = User.query.get(ticket.user_id)
        if user:
            ticket_dict["user_email"] = user.email
            ticket_dict["user_phone"] = user.phone
            ticket_dict["user_name"] = user.name
        tickets_data.append(ticket_dict)

    return jsonify({"tickets": tickets_data, "total": len(tickets_data)}), 200


@support_bp.route("/support/tickets/<int:ticket_id>", methods=["GET"])
def get_ticket(ticket_id):
    """Get detailed ticket information with messages."""
    ticket = SupportTicket.query.get(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404

    messages = TicketMessage.query.filter_by(ticket_id=ticket_id).all()
    user = User.query.get(ticket.user_id)

    ticket_data = ticket.to_dict()
    if user:
        ticket_data["user"] = user.to_dict()
    ticket_data["messages"] = [m.to_dict() for m in messages]

    return jsonify({"ticket": ticket_data}), 200


@support_bp.route("/support/tickets/<int:ticket_id>/messages", methods=["POST"])
@limiter.limit("30 per hour")
def add_message(ticket_id):
    """Add a message to a support ticket."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    ticket = SupportTicket.query.get(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404

    message = TicketMessage(
        ticket_id=ticket_id,
        sender_type=data.get("sender_type", "user"),
        sender_id=data.get("sender_id", 0),
        message=data.get("message", ""),
        attachments=data.get("attachments"),
    )
    db.session.add(message)

    if data.get("status"):
        ticket.status = data["status"]

    db.session.commit()

    user = User.query.get(ticket.user_id)
    logger.info(
        f"Message added to ticket {ticket_id}: sender={message.sender_type}, "
        f"message_length={len(message.message)}, user_email={user.email if user else 'unknown'}"
    )

    return jsonify({
        "message": "Message added successfully",
        "ticket_message": message.to_dict(),
    }), 201


@support_bp.route("/support/tickets/<int:ticket_id>/resolve", methods=["POST"])
def resolve_ticket(ticket_id):
    """Resolve a support ticket."""
    ticket = SupportTicket.query.get(ticket_id)
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404

    ticket.status = "resolved"
    ticket.resolved_at = datetime.utcnow()
    db.session.commit()

    user = User.query.get(ticket.user_id)
    logger.info(
        f"Ticket resolved: ticket_id={ticket_id}, user_id={ticket.user_id}, "
        f"email={user.email if user else 'unknown'}, "
        f"resolved_at={ticket.resolved_at}"
    )

    return jsonify({
        "message": "Ticket resolved successfully",
        "ticket": ticket.to_dict(),
    }), 200
