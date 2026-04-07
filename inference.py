"""Advanced inference script for PrivacyAuditorEnv with retry logic, timeout handling, and strategic agent."""
import json
import os
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, cast

import requests
from openai import OpenAI, APIConnectionError, APITimeoutError, RateLimitError

API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
ENV_BASE_URL = os.getenv("ENV_BASE_URL") or "http://localhost:7860"

TASKS = ["pii_detection", "data_flow_mapping", "compliance_gap_report"]
MAX_STEPS_MAP = {
    "pii_detection": 15,
    "data_flow_mapping": 25,
    "compliance_gap_report": 40,
}

TEMPERATURE = 0.3
MAX_TOKENS = 1024
MAX_RETRIES = 3
RETRY_DELAY = 2
REQUEST_TIMEOUT = 60

SYSTEM_PROMPT = """You are an expert privacy compliance auditor AI. You are auditing a Python Flask web application called "ShopEase India Pvt. Ltd." for privacy violations under GDPR, India's DPDP Act 2023, and CCPA.

The codebase is a realistic e-commerce backend with user authentication, payment processing, analytics integration, and admin panels.

Available actions:
- list_files: List all files in the codebase. Payload: {}
- read_file: Read a source file. Payload: {"filename": "routes/user.py"}
- search_pattern: Grep across files. Payload: {"pattern": "logger.info", "file_glob": "*.py"}
- trace_variable: Follow a variable across files. Payload: {"variable": "user.email", "start_file": "routes/user.py"}
- query_schema: Inspect DB table schema. Payload: {"table": "users"}
- flag_violation: Flag a privacy violation you found. Payload: {"file": "routes/user.py", "line": 42, "violation_type": "pii_logged", "data_type": "email", "description": "User email logged in plaintext", "severity": "high", "article_reference": "GDPR Art. 5"}
- submit_report: Submit your final audit report. Payload: {"findings": [...], "summary": "Audit complete. Found X critical violations."}

Violation types to look for:
- pii_logged: PII (email, phone, PAN, card numbers) written to application logs
- pii_returned: Sensitive data (password_hash, card_number, pan) returned in API responses
- unauthorized_third_party: User data sent to Mixpanel, GA4, Facebook Pixel without consent
- missing_data_deletion: Soft delete instead of hard delete (GDPR Art. 17 violation)
- missing_privacy_notice: No privacy policy or consent mechanism at data collection
- unencrypted_storage: Sensitive fields stored as plaintext in database schema
- weak_password_hashing: Using SHA-256 instead of bcrypt/argon2 for passwords
- excessive_data_collection: Collecting data without clear purpose specification
- missing_access_control: Admin endpoints exposing PII without additional verification
- missing_rate_limiting: Endpoints returning PII without rate limiting

Recommended strategy:
1. Call list_files first to see the full codebase structure
2. Read routes/user.py - highest PII risk (signup, login, profile, delete)
3. Read routes/payment.py - financial data (card numbers, PAN)
4. Search for "logger.info" and "logger.debug" to find PII in logs
5. Search for "to_dict()" to find PII in API responses
6. Read analytics.py for third-party data sharing violations
7. Read schema.sql for unencrypted storage violations
8. Read models.py for data retention and deletion issues
9. Read routes/admin.py for access control issues
10. Flag each violation as you find it with precise file:line references
11. Call submit_report when you are confident or running low on steps

For data_flow_mapping task: Also submit "edges" in your submit_report payload with format:
{"edges": [{"source": "X", "destination": "Y", "data_type": "Z"}, ...]}

For compliance_gap_report task: Submit detailed findings with:
{"findings": [{"article": "GDPR Art. X", "violation": "...", "location": "file.py line N", "severity": "high", "evidence": "code snippet", "recommended_fix": "..."}, ...]}

Respond with ONLY a JSON object:
{"action_type": "...", "payload": {...}}"""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


def call_env_with_retry(endpoint: str, payload: Optional[Dict] = None, method: str = "POST") -> Dict[str, Any]:
    url = f"{ENV_BASE_URL}{endpoint}"
    for attempt in range(MAX_RETRIES):
        try:
            if method == "GET":
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            else:
                resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            raise RuntimeError(f"Failed to connect to environment at {url}: {e}")
        except requests.exceptions.Timeout as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            raise RuntimeError(f"Request to {url} timed out: {e}")
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"HTTP error from {url}: {e}")
    raise RuntimeError("All retries exhausted")


def get_llm_action_with_retry(client: OpenAI, observation: Dict[str, Any], history: List[Dict[str, str]]) -> Dict[str, Any]:
    obs_summary = {
        "task_id": observation.get("task_id"),
        "step": observation.get("step"),
        "max_steps": observation.get("max_steps"),
        "files_available": observation.get("files_available"),
        "action_result_preview": observation.get("action_result", "")[:800],
        "flagged_violations": observation.get("flagged_violations", []),
        "last_error": observation.get("last_action_error"),
        "episode_reward": observation.get("episode_reward_so_far", 0.0),
    }

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]

    for h in history[-8:]:
        messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})

    messages.append({
        "role": "user",
        "content": f"Current state:\n{json.dumps(obs_summary, indent=2, default=str)}\n\nDecide your next action. Respond with ONLY JSON.",
    })

    for attempt in range(MAX_RETRIES):
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=cast(Any, messages),
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                timeout=REQUEST_TIMEOUT,
            )
            response_text = completion.choices[0].message.content
            if response_text is None:
                return {"action_type": "list_files", "payload": {}}

            response_text = response_text.strip()

            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            action = json.loads(response_text)
            if "action_type" not in action:
                return {"action_type": "list_files", "payload": {}}
            return action

        except (APIConnectionError, APITimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {"action_type": "list_files", "payload": {}}
        except RateLimitError as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * 2 * (attempt + 1))
                continue
            return {"action_type": "list_files", "payload": {}}
        except json.JSONDecodeError as e:
            return {"action_type": "list_files", "payload": {}}
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {"action_type": "list_files", "payload": {}}

    return {"action_type": "list_files", "payload": {}}


def run_task(task_id: str, client: OpenAI) -> tuple:
    max_steps = MAX_STEPS_MAP[task_id]

    reset_resp = call_env_with_retry("/reset", {"task_id": task_id, "difficulty": "medium"})
    observation = reset_resp["observation"]

    log_start(task_id, "privacy-auditor-env", MODEL_NAME)

    history = []
    rewards = []
    done = False
    step_count = 0
    last_action_str = "none"

    while not done and step_count < max_steps:
        step_count += 1

        action = get_llm_action_with_retry(client, observation, history)
        action_type = action.get("action_type", "list_files")
        payload = action.get("payload", {})

        action_str = f"{action_type}({json.dumps(payload, default=str)[:100]})"

        step_payload = {"action_type": action_type, "payload": payload}
        step_resp = call_env_with_retry("/step", step_payload)

        obs = step_resp["observation"]
        reward = step_resp["reward"]
        done = step_resp["done"]
        error = obs.get("last_action_error")

        log_step(step_count, action_str, reward, done, error)
        rewards.append(reward)

        history.append({
            "role": "user",
            "content": f"Step {step_count}: Action result: {obs.get('action_result', '')[:400]}",
        })
        history.append({
            "role": "assistant",
            "content": json.dumps(action, default=str),
        })

        observation = obs
        last_action_str = action_str

        if step_count >= max_steps - 2 and not done:
            if action_type != "submit_report":
                action = {"action_type": "submit_report", "payload": {"findings": obs.get("flagged_violations", []), "summary": f"Audit completed after {step_count} steps. Flagged {len(obs.get('flagged_violations', []))} violations."}}
                step_payload = {"action_type": "submit_report", "payload": action["payload"]}
                step_resp = call_env_with_retry("/step", step_payload)
                obs = step_resp["observation"]
                reward = step_resp["reward"]
                done = step_resp["done"]
                error = obs.get("last_action_error")
                step_count += 1
                action_str = f"submit_report({json.dumps(action['payload'], default=str)[:100]})"
                log_step(step_count, action_str, reward, done, error)
                rewards.append(reward)
                break

    score = observation.get("episode_reward_so_far", 0.0)
    success = score > 0.1

    log_end(success, step_count, score, rewards)

    return score, step_count


def main():
    print("=" * 70, flush=True)
    print("PrivacyAuditorEnv - Baseline Inference", flush=True)
    print(f"Model: {MODEL_NAME}", flush=True)
    print(f"Environment: {ENV_BASE_URL}", flush=True)
    print(f"Tasks: {', '.join(TASKS)}", flush=True)
    print("=" * 70, flush=True)

    try:
        client = OpenAI(
            api_key=API_KEY,
            base_url=API_BASE_URL,
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        print(f"ERROR: Failed to initialize OpenAI client: {e}", flush=True)
        print(f"API_BASE_URL: {API_BASE_URL}", flush=True)
        print(f"MODEL_NAME: {MODEL_NAME}", flush=True)
        sys.exit(1)

    all_scores = {}
    all_steps = {}
    start_time = time.time()

    for task_id in TASKS:
        print(f"\n{'=' * 70}", flush=True)
        print(f"Running task: {task_id} (max_steps={MAX_STEPS_MAP[task_id]})", flush=True)
        print(f"{'=' * 70}\n", flush=True)

        task_start = time.time()
        score = 0.0
        steps = 0
        try:
            score, steps = run_task(task_id, client)
            all_scores[task_id] = score
            all_steps[task_id] = steps
        except Exception as e:
            print(f"ERROR running task {task_id}: {e}", flush=True)
            traceback.print_exc()
            all_scores[task_id] = 0.0
            all_steps[task_id] = 0

        task_elapsed = time.time() - task_start
        print(f"Task {task_id} completed in {task_elapsed:.1f}s, score={score:.3f}, steps={steps}", flush=True)

        time.sleep(1)

    total_elapsed = time.time() - start_time

    print(f"\n{'=' * 70}", flush=True)
    print("ALL TASKS COMPLETED", flush=True)
    print(f"Total runtime: {total_elapsed:.1f}s", flush=True)
    print(f"{'=' * 70}", flush=True)

    for task_id in TASKS:
        print(f"  {task_id}: score={all_scores[task_id]:.3f}, steps={all_steps[task_id]}", flush=True)

    total_score = sum(all_scores.values()) / len(all_scores) if all_scores else 0.0
    print(f"\n  Average score: {total_score:.3f}", flush=True)
    print(f"  Total runtime: {total_elapsed:.1f}s", flush=True)

    return all_scores, all_steps


if __name__ == "__main__":
    main()
