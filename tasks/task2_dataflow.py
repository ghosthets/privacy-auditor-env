"""Task 2: Data Flow Mapping - Medium difficulty.

Agent must trace the complete journey of user data from entry points
(signup, login, payment) to all destinations including database tables,
third-party APIs, log files, and analytics SDKs.

Output must be a structured data flow graph with source, destination,
and data_type for each edge.
"""

TASK_ID = "data_flow_mapping"
TASK_NAME = "Data Flow Mapping"
DIFFICULTY = "medium"
MAX_STEPS = 25
DESCRIPTION = (
    "Trace the complete journey of user data from entry points (signup, login, payment) "
    "to all destinations including database tables, third-party APIs (Mixpanel, GA4, "
    "Facebook Pixel), log files, and analytics SDKs. Output a structured data flow graph "
    "with edges containing source, destination, and data_type."
)

GROUND_TRUTH_EDGES = [
    {"source": "signup_form", "destination": "users_table", "data_type": "email, name, phone"},
    {"source": "signup_form", "destination": "mixpanel", "data_type": "email, name, phone"},
    {"source": "signup_form", "destination": "logger", "data_type": "email, name, phone"},
    {"source": "login_form", "destination": "users_table", "data_type": "email, password"},
    {"source": "login_form", "destination": "mixpanel", "data_type": "email"},
    {"source": "login_form", "destination": "logger", "data_type": "email"},
    {"source": "payment_form", "destination": "payments_table", "data_type": "card_number, pan_number"},
    {"source": "payment_form", "destination": "logger", "data_type": "card_number, pan_number, email"},
    {"source": "payment_form", "destination": "mixpanel", "data_type": "email, amount"},
    {"source": "users_table", "destination": "profile_api", "data_type": "email, phone, password_hash, pan_card"},
    {"source": "profile_api", "destination": "logger", "data_type": "email, phone"},
    {"source": "delete_account", "destination": "users_table", "data_type": "is_deleted flag only"},
    {"source": "signup_form", "destination": "ga4_tracker", "data_type": "email, phone"},
    {"source": "signup_form", "destination": "facebook_pixel", "data_type": "email, phone, name"},
    {"source": "admin_panel", "destination": "users_table", "data_type": "all PII fields"},
    {"source": "admin_panel", "destination": "payments_table", "data_type": "card_number, pan_number"},
]

GROUND_TRUTH_NODES = [
    "signup_form",
    "login_form",
    "payment_form",
    "users_table",
    "payments_table",
    "mixpanel",
    "logger",
    "profile_api",
    "delete_account",
    "orders_table",
    "admin_panel",
    "ga4_tracker",
    "facebook_pixel",
    "support_tickets",
    "audit_logs",
]

DATA_CATEGORIES = [
    "email",
    "phone",
    "name",
    "password",
    "password_hash",
    "pan_card",
    "card_number",
    "card_expiry",
    "upi_id",
    "address",
    "date_of_birth",
    "aadhaar_last4",
    "amount",
    "order_id",
    "user_id",
]
