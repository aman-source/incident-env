"""
Incident Response Triage Environment — core Environment subclass.

Implements the OpenEnv Environment interface for incident response simulation.
Manages scenario lifecycle, action processing, reward computation, and cascading effects.
"""

from __future__ import annotations

import copy
from typing import Any, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from incident_env.graders.grader import grade_episode
from incident_env.models import IncidentAction, IncidentObservation, IncidentState
from incident_env.scenarios.base import BaseScenario


# Simulated time cost per action type (seconds)
_TIME_COSTS = {
    "investigate": 15,
    "diagnose": 10,
    "act": 30,
    "escalate": 5,
}

_VALID_ACTION_TYPES = {"investigate", "diagnose", "act", "escalate"}

_VALID_INVESTIGATE_COMMANDS = {"logs", "metrics", "deployments", "dependencies", "config", "overview", "recent_changes"}

_VALID_ACT_COMMANDS = {"restart", "rollback", "scale_up", "scale_down", "flush_cache", "drain_connections", "kill_canary", "failover"}


class IncidentEnvironment(Environment["IncidentAction", "IncidentObservation", "IncidentState"]):
    """Production incident response triage environment.

    The agent receives an alert, investigates services, diagnoses the root cause,
    and takes corrective action — all under simulated time pressure with cascading
    failure dynamics.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self) -> None:
        super().__init__()
        # Lazy imports — scenarios are large files, only load when needed
        from incident_env.scenarios.easy import EasyOOMScenario
        from incident_env.scenarios.medium import MediumDBPoolScenario
        from incident_env.scenarios.hard import HardCanaryScenario

        self._scenario_registry = {
            "easy_oom": EasyOOMScenario,
            "medium_db_pool": MediumDBPoolScenario,
            "hard_canary": HardCanaryScenario,
        }
        self._current_scenario: Optional[BaseScenario] = None
        self._state = IncidentState(episode_id=str(uuid4()), step_count=0)

    # ------------------------------------------------------------------
    # OpenEnv interface
    # ------------------------------------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> IncidentObservation:
        """Reset the environment for a new episode.

        Pass ``task_id`` as a keyword argument to select the scenario.
        Defaults to ``"easy_oom"`` if not specified.
        """
        task_id: str = kwargs.get("task_id", "easy_oom")

        scenario_cls = self._scenario_registry.get(task_id)
        if scenario_cls is None:
            valid = ", ".join(self._scenario_registry.keys())
            return IncidentObservation(
                message=f"Unknown task_id '{task_id}'. Valid tasks: {valid}",
                done=True,
                reward=0.0,
            )

        # Create a fresh scenario instance (deep-copies internal data)
        self._current_scenario = scenario_cls()
        self._state = self._current_scenario.create_initial_state()
        self._state.episode_id = episode_id or str(uuid4())
        self._state.step_count = 0

        obs = self._current_scenario.create_initial_observation()
        obs.metadata = {
            "task_id": task_id,
            "episode_id": self._state.episode_id,
            "max_steps": self._state.max_steps,
        }
        return obs

    def step(
        self,
        action: IncidentAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IncidentObservation:
        """Process one agent action and return an observation."""

        if self._current_scenario is None:
            return IncidentObservation(
                message="No active episode. Call reset() first.",
                done=True,
                reward=0.0,
            )

        state = self._state
        scenario = self._current_scenario

        # Already terminated?
        if state.resolved or state.step_count >= state.max_steps or state.time_elapsed >= state.time_budget:
            grader_result = grade_episode(state, scenario)
            return IncidentObservation(
                message="Episode already terminated.",
                done=True,
                reward=grader_result["score"],
                metadata={"grader": grader_result},
                system_status=scenario.get_system_status_dict(),
                time_elapsed=state.time_elapsed,
                time_budget=state.time_budget,
            )

        state.step_count += 1

        # Validate action type
        action_type = action.action_type.lower().strip()
        if action_type not in _VALID_ACTION_TYPES:
            return self._make_observation(
                message=f"Invalid action_type '{action.action_type}'. Must be one of: {', '.join(_VALID_ACTION_TYPES)}",
                reward=-0.01,
            )

        # Advance simulated time
        time_cost = _TIME_COSTS.get(action_type, 15)
        state.time_elapsed += time_cost

        # Apply cascading effects
        cascade_changes = scenario.apply_cascading_effects(state.time_elapsed)

        # Dispatch to handler
        if action_type == "investigate":
            obs = self._handle_investigate(action, cascade_changes)
        elif action_type == "diagnose":
            obs = self._handle_diagnose(action, cascade_changes)
        elif action_type == "act":
            obs = self._handle_act(action, cascade_changes)
        elif action_type == "escalate":
            obs = self._handle_escalate(action, cascade_changes)
        else:
            obs = self._make_observation(message="Unknown action.", reward=0.0)

        # Check termination conditions
        if state.time_elapsed >= state.time_budget:
            obs.done = True
            obs.message += "\n\n⏰ TIME BUDGET EXHAUSTED. Episode terminated."
            grader_result = grade_episode(state, scenario)
            obs.reward = grader_result["score"]
            obs.metadata["grader"] = grader_result

        if state.step_count >= state.max_steps:
            obs.done = True
            obs.message += "\n\nMax steps reached. Episode terminated."
            grader_result = grade_episode(state, scenario)
            obs.reward = grader_result["score"]
            obs.metadata["grader"] = grader_result

        # Accumulate reward
        if obs.reward is not None:
            state.accumulated_reward += obs.reward

        return obs

    @property
    def state(self) -> IncidentState:
        """Return current internal state."""
        return self._state

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _handle_investigate(self, action: IncidentAction, cascade_changes: list[str]) -> IncidentObservation:
        state = self._state
        scenario = self._current_scenario

        target = action.target.lower().strip()
        command = (action.command or action.parameters.get("check", "logs")).lower().strip()

        if command not in _VALID_INVESTIGATE_COMMANDS:
            return self._make_observation(
                message=f"Unknown investigation command '{command}'. Valid: {', '.join(_VALID_INVESTIGATE_COMMANDS)}",
                reward=-0.01,
            )

        # Track investigation
        inv_key = f"{target}:{command}"
        state.total_investigations += 1

        # Penalise re-investigating the same thing
        if inv_key in state.investigated_targets:
            return self._make_observation(
                message=f"You already investigated {target} {command}. Try something else.",
                investigation_result=f"[Previously retrieved — same data as before]",
                reward=-0.02,
            )

        state.investigated_targets.append(inv_key)
        state.investigation_depth += 1

        # Check relevance
        is_relevant = scenario.is_relevant_investigation(target, command)
        if is_relevant:
            state.correct_investigations += 1

        # Get result text
        result_text = scenario.get_investigation_result(target, command)

        reward = 0.05 if is_relevant else 0.0

        return self._make_observation(
            message=f"Investigation result for {target} → {command}:",
            investigation_result=result_text,
            reward=reward,
            cascade_changes=cascade_changes,
        )

    def _handle_diagnose(self, action: IncidentAction, cascade_changes: list[str]) -> IncidentObservation:
        state = self._state
        scenario = self._current_scenario

        diagnosis = action.command or action.parameters.get("root_cause", "")
        if not diagnosis:
            return self._make_observation(
                message="Diagnosis requires a root_cause description in the 'command' field or parameters.root_cause.",
                reward=0.0,
            )

        # Enforce minimum investigation depth before accepting diagnosis
        min_inv = getattr(scenario, "min_investigations", 1)
        if state.total_investigations < min_inv:
            return self._make_observation(
                message=f"Insufficient investigation. You've only performed {state.total_investigations} investigation(s). "
                        f"Gather more data before diagnosing (minimum {min_inv} investigations required).",
                reward=-0.03,
                cascade_changes=cascade_changes,
            )

        state.agent_diagnosis = diagnosis
        state.diagnosed = True
        state.agent_actions_taken.append(f"diagnose {action.target} {diagnosis}")
        diagnosis_score = scenario.check_diagnosis(diagnosis)

        if diagnosis_score >= 1.0:
            msg = "✅ Diagnosis recorded. Root cause identification looks accurate."
            reward = 0.15
        elif diagnosis_score >= 0.5:
            msg = "⚠️ Diagnosis recorded. Partially correct — some key aspects identified."
            reward = 0.05
        else:
            msg = "❌ Diagnosis recorded. Root cause identification appears incorrect."
            reward = -0.05

        return self._make_observation(
            message=msg,
            action_result=f"Diagnosis submitted: {diagnosis}",
            reward=reward,
            cascade_changes=cascade_changes,
        )

    def _handle_act(self, action: IncidentAction, cascade_changes: list[str]) -> IncidentObservation:
        state = self._state
        scenario = self._current_scenario

        target = action.target.lower().strip()
        command = action.command.lower().strip()

        if command not in _VALID_ACT_COMMANDS:
            return self._make_observation(
                message=f"Unknown act command '{command}'. Valid: {', '.join(_VALID_ACT_COMMANDS)}",
                reward=-0.01,
            )

        action_key = f"{command} {target}"
        state.agent_actions_taken.append(action_key)

        # Check if this action targets a service in the scenario
        if target not in scenario.services:
            state.collateral_damage += 0.1
            return self._make_observation(
                message=f"Service '{target}' not found in the system.",
                action_result=f"Action failed: unknown service '{target}'",
                reward=-0.1,
            )

        # Score resolution
        resolution_score = scenario.score_resolution(state.agent_actions_taken)

        if resolution_score >= 0.7:
            # Correct action — resolve the incident
            state.resolved = True
            svc = scenario.services.get(target)
            if svc:
                svc.status = "healthy"
                svc.error_rate = 0.001
                svc.latency_ms = 50

            grader_result = grade_episode(state, scenario)
            return self._make_observation(
                message=f"✅ Action '{command}' executed on {target}. Incident appears to be resolving!",
                action_result=f"Successfully executed {command} on {target}. System stabilising.",
                reward=grader_result["score"],
                done=True,
                cascade_changes=cascade_changes,
                grader=grader_result,
            )
        else:
            # Wrong or suboptimal action
            is_wrong_target = target not in scenario.root_cause.lower()
            if is_wrong_target:
                state.collateral_damage += 0.1
                reward = -0.1
                msg = f"⚠️ Action '{command}' executed on {target}. No improvement observed — this may not be the root cause."
                result = f"Executed {command} on {target}. Service briefly restarted but issue persists."
            else:
                reward = 0.05
                msg = f"Action '{command}' executed on {target}. Some improvement but issue not fully resolved."
                result = f"Executed {command} on {target}. Partial improvement observed."

            return self._make_observation(
                message=msg,
                action_result=result,
                reward=reward,
                cascade_changes=cascade_changes,
            )

    def _handle_escalate(self, action: IncidentAction, cascade_changes: list[str]) -> IncidentObservation:
        state = self._state

        target_team = action.target.lower().strip()
        priority = action.parameters.get("priority", action.parameters.get("severity", "p2"))

        valid_teams = {"backend", "infrastructure", "database", "security", "management"}
        if target_team not in valid_teams:
            return self._make_observation(
                message=f"Unknown team '{target_team}'. Valid: {', '.join(valid_teams)}",
                reward=-0.01,
            )

        state.agent_actions_taken.append(f"escalate {target_team} {priority}")

        # Escalation scoring
        if state.difficulty == "hard" and priority in ("p1", "P1"):
            reward = 0.02  # Reasonable to escalate hard incidents
            msg = f"📟 Paged {target_team} team at {priority}. They're joining the incident channel."
        elif priority in ("p1", "P1") and state.difficulty == "easy":
            reward = -0.05  # Over-escalation for easy incident
            msg = f"📟 Paged {target_team} team at {priority}. (Note: this incident may not warrant P1 escalation)"
            state.collateral_damage += 0.05
        else:
            reward = 0.0
            msg = f"📟 Paged {target_team} team at {priority}."

        return self._make_observation(
            message=msg,
            action_result=f"Escalation sent to {target_team} at priority {priority}.",
            reward=reward,
            cascade_changes=cascade_changes,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_observation(
        self,
        message: str,
        reward: float = 0.0,
        investigation_result: str = "",
        action_result: str = "",
        done: bool = False,
        cascade_changes: list[str] | None = None,
        grader: dict | None = None,
    ) -> IncidentObservation:
        state = self._state
        scenario = self._current_scenario

        # Append cascade warnings to message
        if cascade_changes:
            message += "\n\n🚨 CASCADING ALERT: " + " | ".join(cascade_changes)
            state.collateral_damage += 0.05 * len(cascade_changes)

        meta: dict[str, Any] = {
            "task_id": state.task_id,
            "episode_id": state.episode_id,
            "step": state.step_count,
        }
        if grader:
            meta["grader"] = grader

        return IncidentObservation(
            message=message,
            alert_summary=scenario.initial_alert if scenario else "",
            system_status=scenario.get_system_status_dict() if scenario else {},
            investigation_result=investigation_result,
            available_actions=scenario.get_available_actions() if scenario else [],
            action_result=action_result,
            time_elapsed=state.time_elapsed,
            time_budget=state.time_budget,
            hint="" if state.investigation_depth < 3 else self._generate_hint(),
            done=done,
            reward=reward,
            metadata=meta,
        )

    def _generate_hint(self) -> str:
        """Generate a contextual hint based on investigation progress."""
        state = self._state
        if state.total_investigations > 0 and state.correct_investigations == 0:
            return "Hint: Consider checking the services mentioned in the alert first."
        if state.total_investigations >= 5 and not state.diagnosed:
            return "Hint: You've gathered significant data. Consider submitting a diagnosis."
        if state.diagnosed and not state.agent_actions_taken:
            return "Hint: You've diagnosed the issue. Now take corrective action."
        return ""

    # ------------------------------------------------------------------
    # Grader access (for /grader endpoint)
    # ------------------------------------------------------------------

    def compute_grader_score(self) -> dict:
        """Compute and return grader score for current episode."""
        if self._current_scenario is None:
            return {"error": "No active episode", "score": 0.0}
        result = grade_episode(self._state, self._current_scenario)
        result["task_id"] = self._state.task_id
        result["episode_id"] = self._state.episode_id
        return result
