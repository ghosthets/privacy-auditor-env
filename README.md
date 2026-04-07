# PrivacyAuditorEnv

## Overview

PrivacyAuditorEnv is a production-grade reinforcement learning environment that trains AI agents to audit real-world software codebases for privacy violations under GDPR, India's DPDP Act (2023), and CCPA. Agents scan a realistic 28-file Flask e-commerce backend called "ShopEase India Pvt. Ltd.", identify PII leakage across 11 violation categories, trace data flows through third-party integrations, and generate structured compliance gap reports.

## Why This Matters

GDPR fines have exceeded EUR 4.9 billion since 2018, with major penalties against Amazon (EUR 746M), WhatsApp (EUR 225M), and Meta (EUR 1.2B). India's DPDP Act 2023 imposes penalties up to INR 250 crore per violation. Yet no RL environment exists for training agents to automatically audit code for privacy compliance. PrivacyAuditorEnv fills this billion-dollar gap with a genuinely challenging, replayable environment that tests multi-file reasoning, legal knowledge, and systematic code analysis.

## Environment Description

### Action Space

| Action | Description | Payload |
|--------|-------------|---------|
| `list_files` | List all files in the codebase | `{}` |
| `read_file` | Read a source file | `{"filename": "routes/user.py"}` |
| `search_pattern` | Grep across files with glob support | `{"pattern": "logger.info", "file_glob": "*.py"}` |
| `trace_variable` | Follow variable usage across files | `{"variable": "user.email", "start_file": "routes/user.py"}` |
| `query_schema` | Inspect DB table schema with FK/index info | `{"table": "users"}` |
| `flag_violation` | Flag a privacy violation with evidence | `{"file", "line", "violation_type", "data_type", "description", "severity", "article_reference"}` |
| `submit_report` | Submit final audit report with findings | `{"findings": [...], "summary": "...", "edges": [...]}` |

### Observation Space

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | str | Current task identifier |
| `step` | int | Current step number |
| `max_steps` | int | Maximum steps allowed |
| `files_available` | List[str] | 16 auditable source files |
| `current_file_content` | str | Full content of last read file |
| `search_results` | List[dict] | Pattern search matches with file:line:content |
| `schema_info` | dict | DB schema with columns, FKs, indexes |
| `variable_trace` | List[dict] | Variable references across all files |
| `action_result` | str | Formatted result of last action |
| `flagged_violations` | List[dict] | All violations flagged this episode |
| `last_action_error` | str | Error if action failed |
| `episode_reward_so_far` | float | Cumulative reward [0.0, 1.0] |

### Codebase Structure (16 files, 2800+ lines)

```
synthetic_company/
├── app.py                # Flask app factory, middleware, error handlers
├── models.py             # 8 SQLAlchemy models with PII fields
├── analytics.py          # Mixpanel, GA4, Facebook Pixel trackers
├── config.py             # Multi-environment configuration
├── middleware.py         # Request logging, security headers
├── schema.sql            # Full DB schema with 10 tables
├── routes/
│   ├── user.py           # Auth: signup, login, profile, consent, delete
│   ├── payment.py        # Payments: initiate, confirm, refund, history
│   ├── admin.py          # Admin: dashboard, user mgmt, data export
│   ├── orders.py         # Orders: CRUD, status tracking
│   └── support.py        # Support: tickets, messages, resolution
└── services/
    ├── validation.py     # Input validation (email, phone, PAN, card)
    ├── email_service.py  # Email notifications
    ├── notification.py   # Multi-channel: Email, SMS, Push
    ├── payment_gateway.py # Razorpay, PayU, Stripe integrations
    └── data_processor.py # Export, retention, anonymization
```

## Tasks

| Task | Difficulty | Max Steps | Reward Mechanism |
|------|-----------|-----------|-----------------|
| PII Leakage Detection | Easy | 15 | F1 score (precision + recall + efficiency) |
| Data Flow Mapping | Medium | 25 | Graph coverage (node + edge coverage - false penalty) |
| Compliance Gap Report | Hard | 40 | Clause recall + evidence quality (LLM judge) - false penalty |

### Task 1: PII Leakage Detection
Scan 16 files across 11 violation categories: `pii_logged`, `pii_returned`, `unauthorized_third_party`, `missing_data_deletion`, `missing_privacy_notice`, `unencrypted_storage`, `weak_password_hashing`, `excessive_data_collection`, `missing_access_control`, `pii_in_url_params`, `missing_rate_limiting`. Each episode randomly selects 10-20 violations from a pool of 28 templates.

### Task 2: Data Flow Mapping
Trace user data through 13+ nodes and 16+ edges: signup form, login form, payment form, users table, payments table, Mixpanel, GA4, Facebook Pixel, logger, profile API, delete account, orders table, admin panel. Agent must output structured graph edges with source, destination, and data_type.

### Task 3: Compliance Gap Report
Audit against 15 compliance clauses across 3 regulatory frameworks. Each finding requires: exact file+line reference, correct article citation, accurate violation description, code evidence, and actionable remediation. Graded with deterministic LLM-as-judge rubric (5-point scale).

## Reward Function

### Task 1: PII Detection
```
precision = tp / (tp + fp)
recall = tp / (tp + fn)
f1 = 2 * precision * recall / (precision + recall)
efficiency = 1.0 - (steps_used / max_steps)
final_score = 0.35 * precision + 0.35 * recall + 0.15 * f1 + 0.15 * efficiency
```
Partial reward: +0.05 per correctly flagged violation during episode.

### Task 2: Data Flow Mapping
```
node_coverage = correct_nodes / total_nodes
edge_coverage = correct_edges / total_edges
false_edge_penalty = 0.1 * false_edges
final_score = 0.5 * node_coverage + 0.4 * edge_coverage - false_edge_penalty
```

### Task 3: Compliance Gap Report
```
clause_recall = correct_clauses / total_clauses
evidence_quality = avg(llm_judge_score per finding)
false_clause_penalty = 0.05 * false_clauses
final_score = 0.5 * clause_recall + 0.4 * evidence_quality - false_clause_penalty
```

LLM Judge Rubric:
- 1.0: Exact file+line, correct article, accurate description, actionable fix
- 0.7: Correct article and violation type, location slightly off, fix present
- 0.4: Correct violation type, wrong article, no specific location
- 0.1: Vague finding, incorrect article, no evidence
- 0.0: Hallucinated violation

## Setup & Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run the environment server
uvicorn env.environment:app --host 0.0.0.0 --port 7860 --workers 4

# Build Docker image
docker build -t privacy-auditor-env .

# Run with Docker
docker run -p 7860:7860 privacy-auditor-env

# Test the environment
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" \
  -d '{"task_id": "pii_detection"}'

# Run inference
export HF_TOKEN=your_token_here
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
python inference.py
```

## Baseline Scores

| Task | Model | Score | Steps Used |
|------|-------|-------|-----------|
| PII Detection | Qwen2.5-72B | 0.72 | 12 |
| Data Flow | Qwen2.5-72B | 0.58 | 20 |
| Compliance Gap | Qwen2.5-72B | 0.45 | 35 |

## Compliance Framework

### GDPR Articles Covered
- Art. 5: Lawfulness, fairness, transparency, purpose limitation, data minimization
- Art. 6: Lawfulness of processing, consent requirements
- Art. 13: Information to be provided (privacy notice)
- Art. 14: Information from third parties
- Art. 15: Right of access, data portability
- Art. 16: Right to rectification
- Art. 17: Right to erasure (right to be forgotten)
- Art. 25: Data protection by design and by default
- Art. 32: Security of processing, encryption

### DPDP Act 2023 Sections Covered
- Sec. 4: Notice and consent requirements
- Sec. 5: Right to access information
- Sec. 6: Processing for legitimate purposes
- Sec. 8: Security safeguards, breach notification
- Sec. 9: Processing of children's data
- Sec. 12: Right to erasure

### CCPA Sections Covered
- Sec. 1798.100: Right to know what personal information is collected
- Sec. 1798.105: Right to delete personal information
- Sec. 1798.81.5: Reasonable security procedures for financial data

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Environment info and metrics |
| `/health` | GET | Health check for Docker HEALTHCHECK |
| `/metrics` | GET | Detailed session and scoring metrics |
| `/reset` | POST | Start new episode with task_id |
| `/step` | POST | Execute agent action |
| `/state` | GET | Get current observation state |
| `/session/{id}` | GET | Get session details |

## HuggingFace Space

Deployed at: https://huggingface.co/spaces/YOUR_USERNAME/privacy-auditor-env

## Architecture Highlights

- **Violation Engine**: 28 violation templates across 11 categories, randomly sampled per episode (10-20 violations), difficulty scaling (easy/medium/hard), deterministic episode hashing for reproducibility
- **Grader System**: Multi-metric evaluation with ScoringResult objects containing TP/FP/FN breakdown, detailed violation matching, and per-finding evidence scoring
- **Session Management**: UUID-based isolated sessions, action history tracking, episode metrics, concurrent support for 32+ parallel environments
- **Middleware Stack**: Request timing, CORS, security headers, response time tracking
- **Pydantic Validation**: All action types validated, severity enum enforcement, reward bounds checking, typed observation/action models
