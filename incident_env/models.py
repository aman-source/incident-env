"""
Data models for the Incident Response Triage Environment.

Defines the action space, observation space, and internal state
using Pydantic models compatible with OpenEnv core v0.2.2.
"""

from typing import Any, Dict, List, Optional

from pydantic import Field

from openenv.core.env_server.types import Action, Observation, State


class IncidentAction(Action):
    """Agent's action in the incident response environment.

    Supports four action types:
    - investigate: Check logs, metrics, deployments, dependencies, or config
    - diagnose: Submit root cause diagnosis
    - act: Take corrective action (restart, rollback, scale_up, etc.)
    - escalate: Page a team with a priority level
    """

    action_type: str = Field(
        ...,
        description="One of: investigate, diagnose, act, escalate",
    )
    target: str = Field(
        ...,
        description="Service or component to target (e.g. 'api-gateway', 'database')",
    )
    command: str = Field(
        default="",
        description="Specific command within the action type (e.g. 'logs', 'restart', 'rollback')",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parameters (e.g. version for rollback, replicas for scale)",
    )


class IncidentObservation(Observation):
    """What the agent sees after each action.

    Inherits done, reward, metadata from Observation base.
    """

    message: str = Field(
        default="",
        description="Human-readable description of what happened",
    )
    alert_summary: str = Field(
        default="",
        description="Current alert details",
    )
    system_status: Dict[str, Any] = Field(
        default_factory=dict,
        description="Service name -> health/latency/error_rate/cpu/memory",
    )
    investigation_result: str = Field(
        default="",
        description="Result of an investigate action (logs, metrics, etc.)",
    )
    available_actions: List[str] = Field(
        default_factory=list,
        description="List of valid action descriptions from current state",
    )
    action_result: str = Field(
        default="",
        description="Result of an act/escalate action",
    )
    time_elapsed: int = Field(
        default=0,
        description="Simulated seconds elapsed in this episode",
    )
    time_budget: int = Field(
        default=300,
        description="Total simulated time budget for this incident",
    )
    hint: str = Field(
        default="",
        description="Optional contextual guidance",
    )


class IncidentState(State):
    """Full internal environment state.

    Extends the base State (episode_id, step_count) with incident-specific fields.
    State has extra='allow' so these additional fields are accepted.
    """

    task_id: str = ""
    difficulty: str = ""
    root_cause: str = ""
    optimal_actions: List[str] = Field(default_factory=list)
    agent_diagnosis: str = ""
    agent_actions_taken: List[str] = Field(default_factory=list)
    services_status: Dict[str, str] = Field(default_factory=dict)
    time_elapsed: int = 0
    time_budget: int = 300
    investigation_depth: int = 0
    correct_investigations: int = 0
    total_investigations: int = 0
    collateral_damage: float = 0.0
    resolved: bool = False
    diagnosed: bool = False
    accumulated_reward: float = 0.0
    investigated_targets: List[str] = Field(default_factory=list)
    max_steps: int = 15
