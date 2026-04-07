-- ShopEase India Pvt. Ltd. - Production Database Schema
-- Supports GDPR Art. 15/17, DPDP Act Sec. 5/12, CCPA compliance requirements

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    phone VARCHAR(15) NOT NULL,
    phone_verified BOOLEAN DEFAULT 0,
    address VARCHAR(255),
    city VARCHAR(50),
    state VARCHAR(50),
    pincode VARCHAR(6),
    password_hash VARCHAR(256) NOT NULL,
    pan_card VARCHAR(10) UNIQUE,
    aadhaar_last4 VARCHAR(4),
    date_of_birth DATE,
    role VARCHAR(20) DEFAULT 'customer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_deleted BOOLEAN DEFAULT 0,
    deleted_at DATETIME,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    referral_code VARCHAR(20) UNIQUE,
    referred_by VARCHAR(20)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_is_deleted ON users(is_deleted);

CREATE TABLE IF NOT EXISTS consent_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    consent_type VARCHAR(30) NOT NULL,
    granted BOOLEAN DEFAULT 1,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_number VARCHAR(20) UNIQUE NOT NULL,
    amount FLOAT NOT NULL,
    tax_amount FLOAT DEFAULT 0.0,
    shipping_amount FLOAT DEFAULT 0.0,
    discount_amount FLOAT DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'pending',
    shipping_address VARCHAR(500),
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    delivered_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_order_number ON orders(order_number);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_name VARCHAR(200) NOT NULL,
    product_sku VARCHAR(50) NOT NULL,
    quantity INTEGER DEFAULT 1,
    unit_price FLOAT NOT NULL,
    total_price FLOAT NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL UNIQUE,
    payment_method VARCHAR(20) DEFAULT 'card',
    card_number VARCHAR(16),
    card_holder_name VARCHAR(100),
    card_expiry VARCHAR(5),
    card_cvv_hash VARCHAR(64),
    pan_number VARCHAR(10),
    upi_id VARCHAR(50),
    bank_account_last4 VARCHAR(4),
    ifsc_code VARCHAR(11),
    transaction_id VARCHAR(50) UNIQUE,
    gateway_response TEXT,
    amount FLOAT NOT NULL,
    currency VARCHAR(3) DEFAULT 'INR',
    status VARCHAR(20) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME,
    refund_amount FLOAT DEFAULT 0.0,
    refund_reason VARCHAR(500),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_order_id ON payments(order_id);

CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_id INTEGER,
    subject VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(30) DEFAULT 'general',
    priority VARCHAR(10) DEFAULT 'medium',
    status VARCHAR(20) DEFAULT 'open',
    assigned_to INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    sender_type VARCHAR(10) NOT NULL,
    sender_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    attachments TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES support_tickets(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    order_id INTEGER,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(30) NOT NULL,
    entity_id INTEGER NOT NULL,
    old_values TEXT,
    new_values TEXT,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

CREATE TABLE IF NOT EXISTS data_export_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    export_file_path VARCHAR(500),
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
