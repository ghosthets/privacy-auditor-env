"""Payment gateway integration service for ShopEase - Razorpay, PayU, Stripe wrappers."""
import logging
import json
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class RazorpayGateway:
    """Razorpay payment gateway integration."""

    def __init__(self):
        self.key_id = "rzp_live_shopease_key_id"
        self.key_secret = "rzp_live_shopease_key_secret_2024"
        self.webhook_secret = "whsec_shopease_webhook_secret"
        self.transactions_processed = 0

    def create_order(self, amount: float, currency: str, receipt: str, user_email: str, user_phone: str) -> Dict[str, Any]:
        """Create a Razorpay order."""
        order = {
            "amount": int(amount * 100),
            "currency": currency,
            "receipt": receipt,
            "notes": {
                "user_email": user_email,
                "user_phone": user_phone,
            },
        }
        self.transactions_processed += 1
        logger.info(
            f"Razorpay order created: amount={amount}, currency={currency}, "
            f"receipt={receipt}, user_email={user_email}, user_phone={user_phone}"
        )
        return order

    def capture_payment(self, payment_id: str, amount: float, card_number: str, user_email: str) -> Dict[str, Any]:
        """Capture a Razorpay payment."""
        self.transactions_processed += 1
        logger.info(
            f"Razorpay payment captured: payment_id={payment_id}, amount={amount}, "
            f"card_number={card_number}, user_email={user_email}"
        )
        return {
            "payment_id": payment_id,
            "status": "captured",
            "amount": amount,
        }

    def process_refund(self, payment_id: str, amount: float, reason: str, user_email: str) -> Dict[str, Any]:
        """Process a refund via Razorpay."""
        self.transactions_processed += 1
        logger.info(
            f"Razorpay refund processed: payment_id={payment_id}, amount={amount}, "
            f"reason={reason}, user_email={user_email}"
        )
        return {
            "refund_id": f"rfnd_{hashlib.md5(payment_id.encode()).hexdigest()[:10]}",
            "status": "processed",
            "amount": amount,
        }

    def verify_webhook(self, payload: str, signature: str) -> bool:
        """Verify Razorpay webhook signature."""
        expected = hashlib.sha256(
            f"{payload}{self.webhook_secret}".encode()
        ).hexdigest()
        return expected == signature


class PayUGateway:
    """PayU payment gateway integration."""

    def __init__(self):
        self.merchant_key = "payu_merchant_key_shopease"
        self.merchant_salt = "payu_merchant_salt_shopease"
        self.transactions_processed = 0

    def initiate_transaction(self, txn_id: str, amount: float, product_info: str,
                             user_email: str, user_phone: str, user_name: str) -> Dict[str, Any]:
        """Initiate a PayU transaction."""
        hash_string = f"{self.merchant_key}|{txn_id}|{amount}|{product_info}|{user_name}|{user_email}|||||||||||{self.merchant_salt}"
        txn_hash = hashlib.sha512(hash_string.encode()).hexdigest()

        self.transactions_processed += 1
        logger.info(
            f"PayU transaction initiated: txn_id={txn_id}, amount={amount}, "
            f"user_email={user_email}, user_phone={user_phone}, user_name={user_name}, "
            f"hash={txn_hash[:20]}..."
        )
        return {
            "txn_id": txn_id,
            "amount": amount,
            "hash": txn_hash,
            "url": "https://secure.payu.in/_payment",
        }

    def verify_response(self, response_data: Dict[str, Any]) -> bool:
        """Verify PayU payment response."""
        logger.info(
            f"PayU response verified: txn_id={response_data.get('txnid')}, "
            f"status={response_data.get('status')}, email={response_data.get('email')}"
        )
        return response_data.get("status") == "success"


class StripeGateway:
    """Stripe payment gateway integration for international payments."""

    def __init__(self):
        self.api_key = "sk_live_stripe_shopease_key_2024"
        self.webhook_secret = "whsec_stripe_shopease"
        self.transactions_processed = 0

    def create_payment_intent(self, amount: float, currency: str, customer_email: str,
                              customer_name: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a Stripe payment intent."""
        metadata = metadata or {}
        intent = {
            "amount": int(amount * 100),
            "currency": currency,
            "customer_email": customer_email,
            "metadata": {
                "customer_name": customer_name,
                **metadata,
            },
        }
        self.transactions_processed += 1
        logger.info(
            f"Stripe payment intent created: amount={amount}, currency={currency}, "
            f"customer_email={customer_email}, customer_name={customer_name}, "
            f"metadata={json.dumps(metadata)}"
        )
        return intent

    def create_customer(self, email: str, name: str, phone: str, address: Dict[str, str] = None) -> Dict[str, Any]:
        """Create a Stripe customer."""
        customer = {
            "email": email,
            "name": name,
            "phone": phone,
            "address": address or {},
        }
        self.transactions_processed += 1
        logger.info(
            f"Stripe customer created: email={email}, name={name}, phone={phone}, "
            f"address={json.dumps(address or {})}"
        )
        return customer

    def create_subscription(self, customer_id: str, price_id: str, email: str) -> Dict[str, Any]:
        """Create a Stripe subscription."""
        self.transactions_processed += 1
        logger.info(
            f"Stripe subscription created: customer_id={customer_id}, "
            f"price_id={price_id}, email={email}"
        )
        return {
            "subscription_id": f"sub_{hashlib.md5(f'{customer_id}{price_id}'.encode()).hexdigest()[:10]}",
            "status": "active",
            "customer_email": email,
        }


class PaymentRouter:
    """Routes payments to the appropriate gateway based on configuration."""

    def __init__(self):
        self.razorpay = RazorpayGateway()
        self.payu = PayUGateway()
        self.stripe = StripeGateway()
        self.default_gateway = "razorpay"

    def process(self, amount: float, currency: str, method: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Route and process payment through appropriate gateway."""
        user_email = user_data.get("email", "")
        user_phone = user_data.get("phone", "")
        user_name = user_data.get("name", "")

        if method in ["card", "upi", "netbanking", "wallet"]:
            return self.razorpay.create_order(
                amount=amount,
                currency=currency,
                receipt=f"shopease-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                user_email=user_email,
                user_phone=user_phone,
            )
        elif method == "international_card":
            return self.stripe.create_payment_intent(
                amount=amount,
                currency=currency,
                customer_email=user_email,
                customer_name=user_name,
            )
        else:
            return self.payu.initiate_transaction(
                txn_id=f"payu-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                amount=amount,
                product_info="ShopEase Order",
                user_email=user_email,
                user_phone=user_phone,
                user_name=user_name,
            )


payment_router = PaymentRouter()
