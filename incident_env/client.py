"""Incident Response Environment Client.

Typed WebSocket client for interacting with the IncidentEnvironment server.
"""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import IncidentAction, IncidentObservation


class IncidentEnv(EnvClient[IncidentAction, IncidentObservation, State]):
    """WebSocket client for the Incident Response Triage Environment.

    Example:
        >>> with IncidentEnv(base_url="http://localhost:7860") as client:
        ...     result = client.reset(task_id="easy_oom")
        ...     print(result.observation.alert_summary)
        ...
        ...     action = IncidentAction(
        ...         action_type="investigate",
        ...         target="api-gateway",
        ...         command="logs",
        ...     )
        ...     result = client.step(action)
        ...     print(result.observation.investigation_result)
    """

    def _step_payload(self, action: IncidentAction) -> Dict:
        """Convert IncidentAction to JSON payload for step message."""
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict) -> StepResult[IncidentObservation]:
        """Parse server response into StepResult[IncidentObservation]."""
        obs_data = payload.get("observation", payload)
        observation = IncidentObservation(**obs_data)

        return StepResult(
            observation=observation,
            reward=payload.get("reward", observation.reward),
            done=payload.get("done", observation.done),
        )

    def _parse_state(self, payload: Dict) -> State:
        """Parse server response into State object."""
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
