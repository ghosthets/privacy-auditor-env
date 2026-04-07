"""PrivacyAuditorEnv package - RL environment for privacy compliance auditing."""
from env.environment import app
from env.models import (
    Action, Observation, StepResponse, ResetResponse, StateResponse,
    FlaggedViolation, DataFlowEdge, ComplianceFinding, TaskInfo,
    EnvMetadata, HealthResponse,
)
from env.violation_engine import ViolationEngine, ViolationTemplate, ALL_VIOLATION_TEMPLATES
from env.grader import (
    grade_pii_detection, grade_data_flow_mapping, grade_compliance_report,
    ScoringResult,
)

__version__ = "1.0.0"
__all__ = [
    "app",
    "Action", "Observation", "StepResponse", "ResetResponse", "StateResponse",
    "FlaggedViolation", "DataFlowEdge", "ComplianceFinding",
    "ViolationEngine", "ViolationTemplate", "ALL_VIOLATION_TEMPLATES",
    "grade_pii_detection", "grade_data_flow_mapping", "grade_compliance_report",
    "ScoringResult",
]
