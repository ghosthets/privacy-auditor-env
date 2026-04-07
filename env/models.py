"""Advanced Pydantic models for PrivacyAuditorEnv with comprehensive typing and validation."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


class Action(BaseModel):
    """Action that the agent can take during privacy audit."""
    action_type: str = Field(
        description="Type of action to perform",
        examples=["list_files", "read_file", "search_pattern", "trace_variable", "query_schema", "flag_violation", "submit_report"],
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters",
    )

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v: str) -> str:
        valid_types = {
            "list_files", "read_file", "search_pattern", "trace_variable",
            "query_schema", "flag_violation", "submit_report",
        }
        if v not in valid_types:
            raise ValueError(f"Invalid action_type: {v}. Must be one of {valid_types}")
        return v


class FlaggedViolation(BaseModel):
    """A violation flagged by the agent during audit."""
    file: str = Field(description="File path where violation was found")
    line: int = Field(description="Line number of the violation", ge=1)
    violation_type: str = Field(description="Type of privacy violation")
    data_type: str = Field(description="Type of data involved in violation")
    description: str = Field(description="Detailed description of the violation")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    article_reference: str = Field(description="Relevant GDPR/DPDP/CCPA article")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid_severities = {"critical", "high", "medium", "low"}
        if v.lower() not in valid_severities:
            raise ValueError(f"Invalid severity: {v}. Must be one of {valid_severities}")
        return v.lower()


class DataFlowEdge(BaseModel):
    """An edge in the data flow graph for Task 2."""
    source: str = Field(description="Source of data flow (e.g., signup_form, users_table)")
    destination: str = Field(description="Destination of data flow (e.g., mixpanel, logger)")
    data_type: str = Field(description="Type of data flowing (e.g., email, phone, card_number)")


class ComplianceFinding(BaseModel):
    """A compliance finding for Task 3."""
    article: str = Field(description="GDPR/DPDP/CCPA article reference")
    violation: str = Field(description="Description of the violation")
    location: str = Field(description="File and line number of the violation")
    severity: str = Field(description="Severity level")
    evidence: str = Field(description="Code evidence supporting the finding")
    recommended_fix: str = Field(description="Recommended remediation")


class Observation(BaseModel):
    """Observation returned to the agent after each step."""
    task_id: str = Field(description="Current task identifier")
    step: int = Field(description="Current step number", ge=0)
    max_steps: int = Field(description="Maximum steps allowed for this task", ge=1)
    files_available: List[str] = Field(default_factory=list, description="List of files available for auditing")
    current_file_content: Optional[str] = Field(default=None, description="Content of the file if read_file was called")
    search_results: Optional[List[Dict[str, Any]]] = Field(default=None, description="Results from search_pattern action")
    schema_info: Optional[Dict[str, Any]] = Field(default=None, description="Database schema information from query_schema")
    variable_trace: Optional[List[Dict[str, Any]]] = Field(default=None, description="Variable trace results from trace_variable")
    action_result: str = Field(default="", description="Plain text result of the last action")
    flagged_violations: List[Dict[str, Any]] = Field(default_factory=list, description="Violations flagged so far this episode")
    last_action_error: Optional[str] = Field(default=None, description="Error message if action failed")
    episode_reward_so_far: float = Field(default=0.0, description="Cumulative reward so far", ge=0.0, le=1.0)


class StepResponse(BaseModel):
    """Response from a step action."""
    observation: Observation
    reward: float = Field(ge=0.0, le=1.0, description="Reward for this step")
    done: bool = Field(description="Whether the episode is complete")
    info: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ResetResponse(BaseModel):
    """Response from a reset action."""
    observation: Observation


class StateResponse(BaseModel):
    """Response from a state query."""
    observation: Observation


class TaskInfo(BaseModel):
    """Information about a task."""
    id: str
    name: str
    difficulty: str
    max_steps: int
    reward_range: List[float] = [0.0, 1.0]


class EnvMetadata(BaseModel):
    """Environment metadata for the root endpoint."""
    name: str
    version: str
    description: str
    tasks: Dict[str, Dict[str, Any]]
    status: str
    uptime_seconds: float
    metrics: Dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: float
    active_sessions: int
    max_concurrent_envs: int
