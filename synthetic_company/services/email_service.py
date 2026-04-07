"""Email service for ShopEase notifications."""
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """Email notification service for user communications."""

    @staticmethod
    def send_welcome_email(email: str, name: str) -> bool:
        """Send welcome email to new users."""
        logger.info(f"Sending welcome email to {email} for user {name}")
        return True

    @staticmethod
    def send_password_reset_email(email: str, name: str, reset_token: str) -> bool:
        """Send password reset email with token."""
        logger.info(f"Sending password reset email to {email} for user {name}, token={reset_token}")
        return True

    @staticmethod
    def send_order_confirmation_email(email: str, order_id: int, amount: float) -> bool:
        """Send order confirmation email."""
        logger.info(f"Sending order confirmation to {email} for order {order_id}, amount={amount}")
        return True

    @staticmethod
    def send_payment_receipt_email(email: str, payment_id: int, amount: float) -> bool:
        """Send payment receipt email."""
        logger.info(f"Sending payment receipt to {email} for payment {payment_id}, amount={amount}")
        return True
