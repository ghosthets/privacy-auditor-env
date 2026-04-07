"""Advanced FastAPI application for PrivacyAuditorEnv with session isolation, metrics, and concurrent support."""
import json
import os
import sys
import time
import uuid
import fnmatch
import logging
from typing import Any, Dict, List, Optional
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from env.models import Action, Observation, StepResponse, ResetResponse, StateResponse
from env.violation_engine import ViolationEngine
from env.grader import grade_pii_detection, grade_data_flow_mapping, grade_compliance_report

logger = logging.getLogger(__name__)

SYNTHETIC_COMPANY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "synthetic_company"
)

TASK_CONFIG = {
    "pii_detection": {
        "name": "PII Leakage Detection",
        "max_steps": 15,
        "difficulty": "easy",
        "description": "Scan the Flask application codebase and identify all locations where user PII is unnecessarily logged or returned in API responses.",
    },
    "data_flow_mapping": {
        "name": "Data Flow Mapping",
        "max_steps": 25,
        "difficulty": "medium",
        "description": "Trace the complete journey of user data from entry points to all destinations including database tables, third-party APIs, log files, and analytics SDKs.",
    },
    "compliance_gap_report": {
        "name": "Compliance Gap Report",
        "max_steps": 40,
        "difficulty": "hard",
        "description": "Generate a structured JSON compliance report auditing the codebase against GDPR Articles and India's DPDP Act Sections.",
    },
}

ACTIVE_FILES = [
    "app.py",
    "models.py",
    "analytics.py",
    "config.py",
    "middleware.py",
    "schema.sql",
    "routes/user.py",
    "routes/payment.py",
    "routes/admin.py",
    "routes/orders.py",
    "routes/support.py",
    "services/validation.py",
    "services/email_service.py",
    "services/notification.py",
    "services/payment_gateway.py",
    "services/data_processor.py",
]

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_METRICS = {
    "total_resets": 0,
    "total_steps": 0,
    "total_episodes_completed": 0,
    "task_distribution": defaultdict(int),
    "average_score_by_task": defaultdict(list),
    "start_time": time.time(),
}


class ResetRequest(BaseModel):
    task_id: str = "pii_detection"
    seed: Optional[int] = None
    difficulty: str = "medium"


class StepRequest(BaseModel):
    action_type: str
    payload: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PrivacyAuditorEnv starting up")
    yield
    logger.info("PrivacyAuditorEnv shutting down")
    SESSIONS.clear()


app = FastAPI(
    title="PrivacyAuditorEnv",
    version="1.0.0",
    description="RL environment for privacy compliance auditing of software systems",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_metrics_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    response.headers["X-Response-Time"] = f"{duration:.4f}s"
    response.headers["X-Env-Version"] = "1.0.0"
    return response


def _get_file_content(filename: str) -> Optional[str]:
    filepath = os.path.join(SYNTHETIC_COMPANY_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return None


def _get_all_files() -> List[str]:
    files = []
    for root, dirs, filenames in os.walk(SYNTHETIC_COMPANY_DIR):
        for fn in filenames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, SYNTHETIC_COMPANY_DIR)
            files.append(rel.replace(os.sep, "/"))
    return sorted(files)


def _search_pattern(pattern: str, file_glob: str = "*.py") -> List[Dict[str, Any]]:
    results = []
    for root, dirs, filenames in os.walk(SYNTHETIC_COMPANY_DIR):
        for fn in filenames:
            if fnmatch.fnmatch(fn, file_glob) or file_glob == "*" or file_glob == "**":
                filepath = os.path.join(root, fn)
                rel = os.path.relpath(filepath, SYNTHETIC_COMPANY_DIR).replace(os.sep, "/")
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line_num, line in enumerate(f, 1):
                            if pattern.lower() in line.lower():
                                results.append({
                                    "file": rel,
                                    "line": line_num,
                                    "content": line.rstrip(),
                                })
                except (UnicodeDecodeError, PermissionError):
                    pass
    return results


def _trace_variable(variable: str, start_file: str = "") -> List[Dict[str, Any]]:
    var_parts = variable.split(".")
    var_name = var_parts[-1] if len(var_parts) > 1 else variable
    obj_name = var_parts[0] if len(var_parts) > 1 else ""
    results = []

    search_files = [start_file] if start_file else []
    if not search_files:
        for root, dirs, filenames in os.walk(SYNTHETIC_COMPANY_DIR):
            for fn in filenames:
                if fn.endswith(".py"):
                    filepath = os.path.join(root, fn)
                    rel = os.path.relpath(filepath, SYNTHETIC_COMPANY_DIR).replace(os.sep, "/")
                    search_files.append(rel)

    for filepath in search_files:
        full_path = os.path.join(SYNTHETIC_COMPANY_DIR, filepath)
        if not os.path.exists(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if var_name in line:
                        context = {
                            "file": filepath,
                            "line": line_num,
                            "content": line.rstrip(),
                        }
                        if obj_name and obj_name in line:
                            context["object_match"] = True
                        results.append(context)
        except (UnicodeDecodeError, PermissionError):
            pass

    return results


def _query_schema(table: str) -> Dict[str, Any]:
    schema_file = os.path.join(SYNTHETIC_COMPANY_DIR, "schema.sql")
    schema_info = {"table": table, "columns": [], "indexes": [], "foreign_keys": []}

    if not os.path.exists(schema_file):
        return schema_info

    with open(schema_file, "r", encoding="utf-8") as f:
        content = f.read()

    in_table = False
    for line in content.split("\n"):
        stripped = line.strip()

        if f"CREATE TABLE" in stripped.upper() and table.lower() in stripped.lower():
            in_table = True
            continue

        if in_table:
            if ");" in stripped:
                in_table = False
                continue

            if not stripped or stripped.startswith("--"):
                continue

            if stripped.upper().startswith("CREATE INDEX"):
                if table.lower() in stripped.lower():
                    schema_info["indexes"].append(stripped.rstrip(","))
                continue

            if stripped.upper().startswith("FOREIGN KEY"):
                schema_info["foreign_keys"].append(stripped.rstrip(","))
                continue

            col_def = stripped.rstrip(",").strip()
            if col_def:
                parts = col_def.split()
                if len(parts) >= 2 and not parts[0].upper().startswith(("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT")):
                    schema_info["columns"].append({
                        "name": parts[0],
                        "type": parts[1],
                        "constraints": " ".join(parts[2:]) if len(parts) > 2 else "",
                    })

    return schema_info


def _build_observation(session: Dict[str, Any], action_result: str = "", error: Optional[str] = None) -> Observation:
    task_id = session["task_id"]
    task_cfg = TASK_CONFIG[task_id]
    return Observation(
        task_id=task_id,
        step=session["step"],
        max_steps=task_cfg["max_steps"],
        files_available=ACTIVE_FILES,
        current_file_content=session.get("current_file_content"),
        search_results=session.get("search_results"),
        schema_info=session.get("schema_info"),
        variable_trace=session.get("variable_trace"),
        action_result=action_result,
        flagged_violations=session.get("flagged_violations", []),
        last_action_error=error,
        episode_reward_so_far=round(session.get("total_reward", 0.0), 4),
    )


@app.get("/")
async def root():
    return {
        "name": "PrivacyAuditorEnv",
        "version": "1.0.0",
        "description": "RL environment for privacy compliance auditing under GDPR, DPDP Act, and CCPA",
        "tasks": {tid: {"name": cfg["name"], "difficulty": cfg["difficulty"], "max_steps": cfg["max_steps"]} for tid, cfg in TASK_CONFIG.items()},
        "status": "running",
        "uptime_seconds": round(time.time() - SESSION_METRICS["start_time"], 2),
        "metrics": {
            "total_resets": SESSION_METRICS["total_resets"],
            "total_steps": SESSION_METRICS["total_steps"],
            "total_episodes_completed": SESSION_METRICS["total_episodes_completed"],
            "active_sessions": len(SESSIONS),
        },
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "timestamp": time.time(),
        "active_sessions": len(SESSIONS),
        "max_concurrent_envs": 32,
    }


@app.get("/metrics")
async def metrics():
    avg_scores = {}
    for task, scores in SESSION_METRICS["average_score_by_task"].items():
        avg_scores[task] = round(sum(scores) / len(scores), 4) if scores else 0.0

    return {
        "total_resets": SESSION_METRICS["total_resets"],
        "total_steps": SESSION_METRICS["total_steps"],
        "total_episodes_completed": SESSION_METRICS["total_episodes_completed"],
        "task_distribution": dict(SESSION_METRICS["task_distribution"]),
        "average_scores": avg_scores,
        "active_sessions": len(SESSIONS),
        "uptime_seconds": round(time.time() - SESSION_METRICS["start_time"], 2),
    }


@app.post("/reset", response_model=ResetResponse)
async def reset(req: ResetRequest = ResetRequest()):
    task_id = req.task_id
    if task_id not in TASK_CONFIG:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown task: {task_id}. Available: {list(TASK_CONFIG.keys())}",
        )

    session_id = str(uuid.uuid4())
    difficulty = req.difficulty or TASK_CONFIG[task_id].get("difficulty", "medium")

    engine = ViolationEngine(seed=req.seed)
    violations = engine.generate(difficulty=difficulty)

    session = {
        "session_id": session_id,
        "task_id": task_id,
        "difficulty": difficulty,
        "step": 0,
        "total_reward": 0.0,
        "done": False,
        "flagged_violations": [],
        "submitted_edges": [],
        "submitted_findings": [],
        "current_file_content": None,
        "search_results": None,
        "schema_info": None,
        "variable_trace": None,
        "violation_engine": engine,
        "ground_truth": engine.get_ground_truth(),
        "episode_info": engine.get_episode_info(),
        "action_history": [],
        "started_at": time.time(),
    }
    SESSIONS[session_id] = session

    SESSION_METRICS["total_resets"] += 1
    SESSION_METRICS["task_distribution"][task_id] += 1

    obs = _build_observation(
        session,
        action_result=(
            f"Environment reset for task '{task_id}' ({difficulty}). "
            f"Episode hash: {session['episode_info']['episode_hash']}. "
            f"Use list_files to begin auditing."
        ),
    )

    return ResetResponse(observation=obs)


@app.post("/step", response_model=StepResponse)
async def step(req: StepRequest):
    action_type = req.action_type
    payload = req.payload

    session_id = payload.get("session_id")
    if not session_id or session_id not in SESSIONS:
        sessions_list = list(SESSIONS.values())
        if sessions_list:
            session = sessions_list[-1]
            session_id = session["session_id"]
        else:
            raise HTTPException(status_code=400, detail="No active session. Call /reset first.")

    session = SESSIONS[session_id]

    if session["done"]:
        obs = _build_observation(
            session,
            action_result="Episode already finished. Call /reset to start a new one.",
        )
        return StepResponse(
            observation=obs,
            reward=0.0,
            done=True,
            info={"message": "Episode already finished", "final_score": session["total_reward"]},
        )

    task_id = session["task_id"]
    task_cfg = TASK_CONFIG[task_id]
    session["step"] += 1
    current_step = session["step"]
    max_steps = task_cfg["max_steps"]

    action_result = ""
    error = None
    reward = 0.0

    try:
        if action_type == "list_files":
            files = _get_all_files()
            action_result = f"Files available ({len(files)}):\n" + "\n".join(f"  - {f}" for f in files)
            session["current_file_content"] = None
            session["search_results"] = None
            session["schema_info"] = None
            session["variable_trace"] = None

        elif action_type == "read_file":
            filename = payload.get("filename", "")
            if not filename:
                error = "filename is required for read_file action"
            else:
                content = _get_file_content(filename)
                if content:
                    action_result = content
                    session["current_file_content"] = content
                else:
                    error = f"File not found: {filename}"
                    action_result = ""
            session["search_results"] = None
            session["schema_info"] = None
            session["variable_trace"] = None

        elif action_type == "search_pattern":
            pattern = payload.get("pattern", "")
            file_glob = payload.get("file_glob", "*.py")
            if not pattern:
                error = "pattern is required for search_pattern action"
            else:
                results = _search_pattern(pattern, file_glob)
                action_result = f"Found {len(results)} matches for pattern '{pattern}' (glob: {file_glob}):\n"
                for r in results[:20]:
                    action_result += f"  {r['file']}:{r['line']} | {r['content'][:120]}\n"
                if len(results) > 20:
                    action_result += f"  ... and {len(results) - 20} more matches"
                session["search_results"] = results
            session["current_file_content"] = None
            session["schema_info"] = None
            session["variable_trace"] = None

        elif action_type == "trace_variable":
            variable = payload.get("variable", "")
            start_file = payload.get("start_file", "")
            if not variable:
                error = "variable is required for trace_variable action"
            else:
                results = _trace_variable(variable, start_file)
                action_result = f"Found {len(results)} references to '{variable}':\n"
                for r in results[:20]:
                    obj_marker = " [OBJ]" if r.get("object_match") else ""
                    action_result += f"  {r['file']}:{r['line']}{obj_marker} | {r['content'][:120]}\n"
                if len(results) > 20:
                    action_result += f"  ... and {len(results) - 20} more references"
                session["variable_trace"] = results
            session["current_file_content"] = None
            session["search_results"] = None
            session["schema_info"] = None

        elif action_type == "query_schema":
            table = payload.get("table", "")
            if not table:
                error = "table is required for query_schema action"
            else:
                info = _query_schema(table)
                if info["columns"]:
                    action_result = f"Schema for table '{table}':\n"
                    for col in info["columns"]:
                        action_result += f"  {col['name']} {col['type']} {col.get('constraints', '')}\n"
                    if info["foreign_keys"]:
                        action_result += "\nForeign Keys:\n"
                        for fk in info["foreign_keys"]:
                            action_result += f"  {fk}\n"
                    if info["indexes"]:
                        action_result += "\nIndexes:\n"
                        for idx in info["indexes"]:
                            action_result += f"  {idx}\n"
                else:
                    action_result = f"Table '{table}' not found in schema."
                session["schema_info"] = info
            session["current_file_content"] = None
            session["search_results"] = None
            session["variable_trace"] = None

        elif action_type == "flag_violation":
            required_fields = ["file", "line", "violation_type", "data_type", "description", "severity", "article_reference"]
            missing = [f for f in required_fields if not payload.get(f)]
            if missing:
                error = f"Missing required fields for flag_violation: {', '.join(missing)}"
            else:
                violation = {
                    "file": payload["file"],
                    "line": int(payload["line"]),
                    "violation_type": payload["violation_type"],
                    "data_type": payload["data_type"],
                    "description": payload["description"],
                    "severity": payload["severity"],
                    "article_reference": payload["article_reference"],
                }
                session["flagged_violations"].append(violation)
                action_result = f"Violation flagged: {violation['violation_type']} in {violation['file']}:{violation['line']}"

                for gt in session["ground_truth"]:
                    if violation["file"] == gt["file"] and violation["violation_type"] == gt["violation_type"]:
                        reward = 0.05
                        break

            session["current_file_content"] = None
            session["search_results"] = None
            session["schema_info"] = None
            session["variable_trace"] = None

        elif action_type == "submit_report":
            findings = payload.get("findings", [])
            summary = payload.get("summary", "")
            edges = payload.get("edges", [])

            if findings:
                session["submitted_findings"] = findings
            if edges:
                session["submitted_edges"] = edges

            session["flagged_violations"].extend(findings)
            steps_used = current_step

            if task_id == "pii_detection":
                scoring_result = grade_pii_detection(
                    session["flagged_violations"],
                    session["ground_truth"],
                    steps_used,
                    max_steps,
                )
                reward = scoring_result.final_score

            elif task_id == "data_flow_mapping":
                ground_truth_edges = [
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
                ]
                ground_truth_nodes = [
                    "signup_form", "login_form", "payment_form", "users_table",
                    "payments_table", "mixpanel", "logger", "profile_api",
                    "delete_account", "orders_table", "admin_panel", "ga4_tracker",
                    "facebook_pixel",
                ]
                edges_to_grade = edges if edges else session.get("submitted_edges", [])
                scoring_result = grade_data_flow_mapping(
                    edges_to_grade, ground_truth_edges, ground_truth_nodes
                )
                reward = scoring_result.final_score

            elif task_id == "compliance_gap_report":
                ground_truth_clauses = [
                    "GDPR Art. 5", "GDPR Art. 6", "GDPR Art. 13", "GDPR Art. 17",
                    "GDPR Art. 32",
                    "DPDP Act Sec. 4", "DPDP Act Sec. 5", "DPDP Act Sec. 6",
                    "DPDP Act Sec. 8", "DPDP Act Sec. 12",
                ]
                ground_truth_findings = session["ground_truth"]
                findings_to_grade = findings if findings else session.get("submitted_findings", [])
                scoring_result = grade_compliance_report(
                    findings_to_grade, ground_truth_clauses, ground_truth_findings
                )
                reward = scoring_result.final_score

            session["done"] = True
            action_result = f"Report submitted. Final score: {reward:.4f}. Summary: {summary[:200] if summary else 'No summary provided'}"

        else:
            error = f"Unknown action type: {action_type}. Valid types: list_files, read_file, search_pattern, trace_variable, query_schema, flag_violation, submit_report"

    except Exception as e:
        error = str(e)
        action_result = ""
        logger.exception(f"Error processing action {action_type}: {e}")

    session["action_history"].append({
        "step": current_step,
        "action_type": action_type,
        "payload": {k: v for k, v in payload.items() if k != "session_id"},
        "reward": reward,
        "error": error,
    })

    session["total_reward"] += reward

    done = session["done"] or current_step >= max_steps
    if done and not session["done"]:
        session["done"] = True
        steps_used = current_step

        if task_id == "pii_detection":
            scoring_result = grade_pii_detection(
                session["flagged_violations"],
                session["ground_truth"],
                steps_used,
                max_steps,
            )
            reward = scoring_result.final_score
            session["total_reward"] = reward

        elif task_id == "data_flow_mapping":
            ground_truth_edges = [
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
            ]
            ground_truth_nodes = [
                "signup_form", "login_form", "payment_form", "users_table",
                "payments_table", "mixpanel", "logger", "profile_api",
                "delete_account", "orders_table", "admin_panel", "ga4_tracker",
                "facebook_pixel",
            ]
            scoring_result = grade_data_flow_mapping(
                session.get("submitted_edges", []),
                ground_truth_edges,
                ground_truth_nodes,
            )
            reward = scoring_result.final_score
            session["total_reward"] = reward

        elif task_id == "compliance_gap_report":
            ground_truth_clauses = [
                "GDPR Art. 5", "GDPR Art. 6", "GDPR Art. 13", "GDPR Art. 17",
                "GDPR Art. 32",
                "DPDP Act Sec. 4", "DPDP Act Sec. 5", "DPDP Act Sec. 6",
                "DPDP Act Sec. 8", "DPDP Act Sec. 12",
            ]
            ground_truth_findings = session["ground_truth"]
            scoring_result = grade_compliance_report(
                session.get("submitted_findings", []),
                ground_truth_clauses,
                ground_truth_findings,
            )
            reward = scoring_result.final_score
            session["total_reward"] = reward

        SESSION_METRICS["total_episodes_completed"] += 1
        SESSION_METRICS["average_score_by_task"][task_id].append(session["total_reward"])

    reward = max(0.0, min(1.0, reward))
    SESSION_METRICS["total_steps"] += 1

    obs = _build_observation(session, action_result=action_result, error=error)

    info = {
        "task_id": task_id,
        "difficulty": session.get("difficulty", "medium"),
        "steps_used": current_step,
        "steps_remaining": max(0, max_steps - current_step),
        "episode_hash": session.get("episode_info", {}).get("episode_hash", ""),
    }
    if session["done"]:
        info["final_score"] = round(session["total_reward"], 4)
        info["episode_duration_seconds"] = round(time.time() - session.get("started_at", time.time()), 2)

    return StepResponse(observation=obs, reward=reward, done=done, info=info)


@app.get("/state", response_model=StateResponse)
async def get_state():
    sessions_list = list(SESSIONS.values())
    if not sessions_list:
        raise HTTPException(status_code=400, detail="No active session. Call /reset first.")

    session = sessions_list[-1]
    obs = _build_observation(session)
    return StateResponse(observation=obs)


@app.get("/session/{session_id}")
async def get_session(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    session = SESSIONS[session_id]
    return {
        "session_id": session_id,
        "task_id": session["task_id"],
        "difficulty": session.get("difficulty", "medium"),
        "step": session["step"],
        "done": session["done"],
        "total_reward": round(session["total_reward"], 4),
        "flagged_violations_count": len(session["flagged_violations"]),
        "episode_info": session.get("episode_info", {}),
        "action_count": len(session.get("action_history", [])),
    }
