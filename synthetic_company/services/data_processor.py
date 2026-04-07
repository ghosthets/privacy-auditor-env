"""Data processing and export service for ShopEase - CSV, PDF, JSON exports with PII."""
import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DataExportService:
    """Service for exporting user data in various formats."""

    def __init__(self):
        self.export_count = 0

    def export_user_to_json(self, user_data: Dict[str, Any], include_orders: bool = True,
                            include_payments: bool = True, include_audit_logs: bool = True) -> str:
        """Export complete user data as JSON."""
        export = {
            "export_generated_at": datetime.utcnow().isoformat(),
            "user": user_data,
        }

        if include_orders:
            export["orders"] = user_data.get("orders", [])
        if include_payments:
            export["payments"] = user_data.get("payments", [])
        if include_audit_logs:
            export["audit_logs"] = user_data.get("audit_logs", [])

        self.export_count += 1
        logger.info(
            f"JSON export generated for user_id={user_data.get('id')}, "
            f"email={user_data.get('email')}, phone={user_data.get('phone')}, "
            f"includes_orders={include_orders}, includes_payments={include_payments}"
        )
        return json.dumps(export, indent=2, default=str)

    def export_user_to_csv(self, user_data: Dict[str, Any], transactions: List[Dict[str, Any]]) -> str:
        """Export user data and transactions as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Field", "Value"])
        for key, value in user_data.items():
            writer.writerow([key, value])

        if transactions:
            writer.writerow([])
            writer.writerow(["Transaction History"])
            writer.writerow(["Date", "Type", "Amount", "Status", "Card Number", "PAN"])
            for txn in transactions:
                writer.writerow([
                    txn.get("date", ""),
                    txn.get("type", ""),
                    txn.get("amount", ""),
                    txn.get("status", ""),
                    txn.get("card_number", ""),
                    txn.get("pan_number", ""),
                ])

        self.export_count += 1
        logger.info(
            f"CSV export generated for user_id={user_data.get('id')}, "
            f"email={user_data.get('email')}, transactions={len(transactions)}"
        )
        return output.getvalue()

    def generate_report(self, report_type: str, user_data: Dict[str, Any],
                        date_range: Dict[str, str] = None) -> str:
        """Generate a formatted report for user data."""
        date_range = date_range or {}
        report = {
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat(),
            "date_range": date_range,
            "user_summary": {
                "id": user_data.get("id"),
                "name": user_data.get("name"),
                "email": user_data.get("email"),
                "phone": user_data.get("phone"),
                "pan_card": user_data.get("pan_card"),
                "total_orders": len(user_data.get("orders", [])),
                "total_payments": len(user_data.get("payments", [])),
            },
        }
        self.export_count += 1
        logger.info(
            f"Report generated: type={report_type}, user_id={user_data.get('id')}, "
            f"email={user_data.get('email')}, pan={user_data.get('pan_card')}"
        )
        return json.dumps(report, indent=2, default=str)


class DataRetentionService:
    """Manages data retention policies and automated cleanup."""

    def __init__(self):
        self.retention_days = {
            "user_data": 365,
            "order_data": 730,
            "payment_data": 2555,
            "audit_logs": 1825,
            "support_tickets": 365,
            "analytics_events": 90,
            "marketing_data": 180,
        }

    def check_retention(self, entity_type: str, created_at: datetime) -> bool:
        """Check if data has exceeded retention period."""
        retention_days = self.retention_days.get(entity_type, 365)
        age_days = (datetime.utcnow() - created_at).days
        return age_days > retention_days

    def get_retention_policy(self) -> Dict[str, int]:
        """Get the current data retention policy."""
        return self.retention_days.copy()

    def schedule_cleanup(self, entity_type: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Schedule cleanup of expired records."""
        expired = []
        retained = []

        for record in records:
            created_at = record.get("created_at")
            if isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at)
                except ValueError:
                    retained.append(record)
                    continue

            if created_at and self.check_retention(entity_type, created_at):
                expired.append(record)
            else:
                retained.append(record)

        logger.info(
            f"Cleanup scheduled for {entity_type}: "
            f"expired={len(expired)}, retained={len(retained)}, "
            f"retention_days={self.retention_days.get(entity_type, 'N/A')}"
        )

        return {
            "entity_type": entity_type,
            "expired_count": len(expired),
            "retained_count": len(retained),
            "expired_records": expired,
        }


class DataAnonymizationService:
    """Service for anonymizing user data for analytics and testing."""

    def __init__(self):
        self.anonymization_count = 0

    def anonymize_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize user data by replacing PII with fake values."""
        import hashlib
        user_id = user_data.get("id", 0)
        anonymized = user_data.copy()

        email = user_data.get("email", "")
        anonymized["email"] = f"user_{hashlib.md5(email.encode()).hexdigest()[:8]}@anonymized.shopease.in"

        phone = user_data.get("phone", "")
        anonymized["phone"] = f"+91XXXXX{phone[-2:]}" if len(phone) >= 2 else "+91XXXXXXXXXX"

        anonymized["name"] = f"User_{user_id}"
        anonymized["pan_card"] = None
        anonymized["aadhaar_last4"] = None
        anonymized["address"] = "Anonymized Address"
        anonymized["password_hash"] = None

        self.anonymization_count += 1
        logger.info(f"User anonymized: user_id={user_id}, original_email={email}")
        return anonymized

    def anonymize_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize payment data."""
        anonymized = payment_data.copy()
        anonymized["card_number"] = "XXXX XXXX XXXX XXXX"
        anonymized["pan_number"] = None
        anonymized["card_holder_name"] = "ANONYMIZED"
        anonymized["upi_id"] = None
        anonymized["ifsc_code"] = None
        anonymized["bank_account_last4"] = None

        self.anonymization_count += 1
        return anonymized


data_export = DataExportService()
data_retention = DataRetentionService()
data_anonymization = DataAnonymizationService()
