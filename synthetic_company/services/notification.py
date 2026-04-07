"""Notification service for ShopEase - Email, SMS, Push notifications."""
import logging
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EmailProvider:
    """Email delivery service wrapper."""

    def __init__(self, provider: str = "sendgrid"):
        self.provider = provider
        self.api_key = "sk-sendgrid-prod-key-shopease-2024"
        self.from_email = "noreply@shopease.in"
        self.from_name = "ShopEase India"
        self.sent_count = 0

    def send(self, to_email: str, subject: str, body: str, html_body: str = None, user_name: str = None) -> bool:
        """Send an email notification."""
        payload = {
            "to": to_email,
            "from": f"{self.from_name} <{self.from_email}>",
            "subject": subject,
            "text": body,
            "html": html_body or body,
            "user_name": user_name,
        }
        self.sent_count += 1
        logger.info(
            f"Email sent via {self.provider}: to={to_email}, subject={subject}, "
            f"user_name={user_name}, payload={json.dumps(payload)}"
        )
        return True

    def send_transactional(self, to_email: str, template: str, user_data: Dict[str, Any]) -> bool:
        """Send a transactional email using a template."""
        logger.info(
            f"Transactional email sent: to={to_email}, template={template}, "
            f"user_data={json.dumps(user_data)}"
        )
        self.sent_count += 1
        return True


class SMSProvider:
    """SMS delivery service wrapper."""

    def __init__(self, provider: str = "twilio"):
        self.provider = provider
        self.auth_token = "twilio-auth-token-shopease"
        self.account_sid = "AC-shopease-account-sid"
        self.from_number = "+919876543210"
        self.sent_count = 0

    def send(self, to_phone: str, message: str, user_name: str = None, user_email: str = None) -> bool:
        """Send an SMS notification."""
        self.sent_count += 1
        logger.info(
            f"SMS sent via {self.provider}: to={to_phone}, user_name={user_name}, "
            f"user_email={user_email}, message_length={len(message)}"
        )
        return True

    def send_otp(self, to_phone: str, otp: str, user_id: int = None) -> bool:
        """Send an OTP via SMS."""
        self.sent_count += 1
        logger.info(
            f"OTP sent via {self.provider}: to={to_phone}, otp={otp}, user_id={user_id}"
        )
        return True


class PushNotificationProvider:
    """Push notification delivery service."""

    def __init__(self, provider: str = "firebase"):
        self.provider = provider
        self.server_key = "firebase-server-key-shopease-2024"
        self.sent_count = 0

    def send(self, device_token: str, title: str, body: str, user_data: Dict[str, Any] = None) -> bool:
        """Send a push notification."""
        user_data = user_data or {}
        self.sent_count += 1
        logger.info(
            f"Push notification sent via {self.provider}: "
            f"title={title}, user_data={json.dumps(user_data)}"
        )
        return True


class NotificationService:
    """Unified notification service coordinating email, SMS, and push."""

    def __init__(self):
        self.email = EmailProvider()
        self.sms = SMSProvider()
        self.push = PushNotificationProvider()

    def notify_user(self, user_id: int, email: str, phone: str, name: str,
                    channels: List[str], subject: str, message: str,
                    user_data: Dict[str, Any] = None) -> Dict[str, bool]:
        """Send notification across multiple channels."""
        user_data = user_data or {}
        results = {}

        if "email" in channels:
            results["email"] = self.email.send(
                to_email=email,
                subject=subject,
                body=message,
                user_name=name,
            )

        if "sms" in channels:
            results["sms"] = self.sms.send(
                to_phone=phone,
                message=message,
                user_name=name,
                user_email=email,
            )

        if "push" in channels:
            results["push"] = self.push.send(
                device_token=user_data.get("device_token", ""),
                title=subject,
                body=message,
                user_data={"user_id": user_id, "email": email, "name": name, **user_data},
            )

        logger.info(
            f"Multi-channel notification sent to user_id={user_id}, "
            f"email={email}, phone={phone}, name={name}, "
            f"channels={channels}, results={results}"
        )

        return results

    def send_order_confirmation(self, user_id: int, email: str, phone: str, name: str,
                                order_id: int, amount: float) -> Dict[str, bool]:
        """Send order confirmation across all channels."""
        subject = f"Order Confirmed - #{order_id}"
        message = f"Your order #{order_id} for Rs. {amount:.2f} has been confirmed."
        return self.notify_user(
            user_id=user_id, email=email, phone=phone, name=name,
            channels=["email", "sms"],
            subject=subject, message=message,
            user_data={"order_id": order_id, "amount": amount},
        )

    def send_payment_receipt(self, user_id: int, email: str, name: str,
                             payment_id: int, amount: float, card_last4: str) -> bool:
        """Send payment receipt via email."""
        subject = f"Payment Receipt - #{payment_id}"
        body = f"Payment of Rs. {amount:.2f} received. Card ending {card_last4}."
        return self.email.send(
            to_email=email,
            subject=subject,
            body=body,
            user_name=name,
        )


notification_service = NotificationService()
