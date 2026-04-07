"""Advanced analytics module - Third party SDK integrations with PII leakage."""
import logging
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MixpanelTracker:
    """Mixpanel analytics tracker with event queuing and batching."""

    def __init__(self, token: str = None, batch_size: int = 50):
        self.token = token or "mixpanel-prod-token-shopease-2024"
        self.batch_size = batch_size
        self.queue: List[Dict[str, Any]] = []
        self.flush_count = 0
        self.total_events_tracked = 0

    def track(self, event_name: str, properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Track an event with Mixpanel SDK."""
        properties = properties or {}
        event = {
            "event": event_name,
            "properties": {
                "token": self.token,
                "time": datetime.utcnow().timestamp(),
                "distinct_id": properties.get("user_id", "anonymous"),
                **properties,
            },
        }
        self.queue.append(event)
        self.total_events_tracked += 1

        logger.info(
            f"Mixpanel event tracked: event={event_name}, "
            f"properties={json.dumps(properties)}, "
            f"queue_size={len(self.queue)}, "
            f"total_events={self.total_events_tracked}"
        )

        if len(self.queue) >= self.batch_size:
            self.flush()

        return event

    def track_signup(self, user_id: int, email: str, name: str, phone: str) -> Dict[str, Any]:
        """Track user signup event with full PII."""
        return self.track("user_signup", {
            "user_id": user_id,
            "email": email,
            "name": name,
            "phone": phone,
            "signup_source": "web",
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_login(self, user_id: int, email: str, ip_address: str = None) -> Dict[str, Any]:
        """Track user login event."""
        return self.track("user_login", {
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address or "unknown",
            "login_method": "email_password",
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_logout(self, user_id: int, email: str) -> Dict[str, Any]:
        """Track user logout event."""
        return self.track("user_logout", {
            "user_id": user_id,
            "email": email,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_purchase(self, user_id: int, order_id: int, amount: float, email: str, items_count: int = 1) -> Dict[str, Any]:
        """Track purchase event with transaction details."""
        return self.track("purchase_completed", {
            "user_id": user_id,
            "order_id": order_id,
            "amount": amount,
            "email": email,
            "items_count": items_count,
            "currency": "INR",
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_page_view(self, user_id: int, page: str, email: str, referrer: str = None) -> Dict[str, Any]:
        """Track page view event."""
        return self.track("page_view", {
            "user_id": user_id,
            "page": page,
            "email": email,
            "referrer": referrer or "direct",
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_profile_update(self, user_id: int, email: str, fields_updated: List[str]) -> Dict[str, Any]:
        """Track profile update event."""
        return self.track("profile_updated", {
            "user_id": user_id,
            "email": email,
            "fields_updated": fields_updated,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_account_deletion(self, user_id: int, email: str, reason: str = None) -> Dict[str, Any]:
        """Track account deletion event."""
        return self.track("account_deletion_requested", {
            "user_id": user_id,
            "email": email,
            "reason": reason or "not_specified",
            "timestamp": datetime.utcnow().isoformat(),
        })

    def track_error(self, error_type: str, error_message: str, user_id: int = None, email: str = None) -> Dict[str, Any]:
        """Track application error event."""
        return self.track("application_error", {
            "error_type": error_type,
            "error_message": error_message,
            "user_id": user_id,
            "email": email,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def flush(self) -> int:
        """Send queued events to Mixpanel API endpoint."""
        count = len(self.queue)
        if count == 0:
            return 0

        logger.info(
            f"Flushing {count} events to Mixpanel endpoint "
            f"https://api.mixpanel.com/track, batch_id={self.flush_count}"
        )
        self.flush_count += 1
        self.queue.clear()
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get tracker statistics."""
        return {
            "total_events_tracked": self.total_events_tracked,
            "queue_size": len(self.queue),
            "flush_count": self.flush_count,
            "token": self.token,
        }


class GoogleAnalyticsTracker:
    """Google Analytics 4 tracker for web analytics."""

    def __init__(self, measurement_id: str = None, api_secret: str = None):
        self.measurement_id = measurement_id or "G-SHOPEASE2024"
        self.api_secret = api_secret or "ga4-secret-key-shopease"
        self.events_sent = 0

    def send_event(self, event_name: str, user_properties: Dict[str, Any], event_params: Dict[str, Any]) -> Dict[str, Any]:
        """Send event to Google Analytics 4."""
        payload = {
            "client_id": user_properties.get("user_id", "anonymous"),
            "events": [{
                "name": event_name,
                "params": {
                    **event_params,
                    "user_email": user_properties.get("email", ""),
                    "user_phone": user_properties.get("phone", ""),
                },
            }],
        }

        self.events_sent += 1
        logger.info(
            f"GA4 event sent: event={event_name}, "
            f"measurement_id={self.measurement_id}, "
            f"total_events={self.events_sent}"
        )

        return payload


class FacebookPixelTracker:
    """Facebook Pixel tracker for conversion tracking."""

    def __init__(self, pixel_id: str = None):
        self.pixel_id = pixel_id or "123456789012345"
        self.events_sent = 0

    def track_conversion(self, event_name: str, user_data: Dict[str, Any], custom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Track conversion event with Facebook Pixel."""
        payload = {
            "event_name": event_name,
            "event_source_url": "https://shopease.in",
            "user_data": {
                "em": user_data.get("email", ""),
                "ph": user_data.get("phone", ""),
                "fn": user_data.get("name", ""),
            },
            "custom_data": custom_data,
        }

        self.events_sent += 1
        logger.info(
            f"Facebook Pixel conversion tracked: event={event_name}, "
            f"pixel_id={self.pixel_id}, total={self.events_sent}"
        )

        return payload


tracker = MixpanelTracker()
ga_tracker = GoogleAnalyticsTracker()
fb_pixel = FacebookPixelTracker()
