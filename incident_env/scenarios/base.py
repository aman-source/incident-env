"""Base scenario class for incident response scenarios.

Defines the contract that all concrete scenarios (easy, medium, hard) must
implement.  Also provides shared helper logic for cascading degradation,
diagnosis checking, investigation lookups, and system-status serialisation.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Set, Tuple

from incident_env.models import IncidentObservation, IncidentState


# ---------------------------------------------------------------------------
# Supporting data classes
# ---------------------------------------------------------------------------

class CascadingEffect:
    """A system degradation that triggers after a simulated-time threshold.

    When ``time_elapsed`` reaches ``time_threshold`` and the target service
    is not already in the degraded state, the effect is applied.
    """

    def __init__(
        self,
        time_threshold: int,
        service: str,
        effect: str,
        description: str,
    ) -> None:
        self.time_threshold = time_threshold
        self.service = service
        self.effect = effect  # "degraded" | "down" | "slow"
        self.description = description
        self.applied = False  # track whether this effect has fired


class ServiceInfo:
    """Runtime information about a single service in the simulated stack."""

    def __init__(
        self,
        name: str,
        status: str = "healthy",
        latency_ms: int = 45,
        error_rate: float = 0.001,
        cpu_pct: float = 35.0,
        memory_pct: float = 50.0,
        dependencies: List[str] | None = None,
        recent_deploys: List[Dict[str, Any]] | None = None,
        logs: List[str] | None = None,
    ) -> None:
        self.name = name
        self.status = status
        self.latency_ms = latency_ms
        self.error_rate = error_rate
        self.cpu_pct = cpu_pct
        self.memory_pct = memory_pct
        self.dependencies: List[str] = dependencies or []
        self.recent_deploys: List[Dict[str, Any]] = recent_deploys or []
        self.logs: List[str] = logs or []

    def to_status_dict(self) -> Dict[str, Any]:
        """Serialise to a compact dict suitable for observations."""
        return {
            "status": self.status,
            "latency_ms": self.latency_ms,
            "error_rate": round(self.error_rate, 4),
            "cpu_pct": round(self.cpu_pct, 1),
            "memory_pct": round(self.memory_pct, 1),
        }


# ---------------------------------------------------------------------------
# Abstract base scenario
# ---------------------------------------------------------------------------

class BaseScenario(ABC):
    """Abstract base for all incident scenarios.

    Concrete subclasses must set every class-level attribute and implement
    the three abstract methods.  The base class provides shared helpers that
    the environment calls during ``step()``.
    """

    # -- Identity -----------------------------------------------------------
    task_id: str
    name: str
    difficulty: str  # "easy" | "medium" | "hard"
    description: str

    # -- System topology ----------------------------------------------------
    services: Dict[str, ServiceInfo]

    # -- Alert --------------------------------------------------------------
    initial_alert: str

    # -- Investigation data -------------------------------------------------
    # key = (target_service, check_command), value = text result
    investigation_results: Dict[Tuple[str, str], str]

    # -- Ground truth -------------------------------------------------------
    root_cause: str
    root_cause_keywords: Set[str]
    optimal_actions: List[str]

    # -- Timing -------------------------------------------------------------
    time_budget: int          # total simulated seconds for this incident
    max_steps: int            # maximum agent steps before episode ends

    # Minimum investigations required before diagnosis is accepted
    min_investigations: int = 1

    # Simulated wall-clock cost of each action type (seconds)
    time_costs: Dict[str, int] = {
        "investigate": 15,
        "diagnose": 10,
        "act": 30,
        "escalate": 5,
    }

    # -- Cascading effects --------------------------------------------------
    cascading_effects: List[CascadingEffect]

    # -- Red herrings -------------------------------------------------------
    # Same key shape as investigation_results; looked up as fallback
    red_herrings: Dict[Tuple[str, str], str]

    # -- Relevance set for reward calc --------------------------------------
    relevant_investigations: Set[Tuple[str, str]]

    # -----------------------------------------------------------------------
    # Abstract methods — subclasses MUST implement
    # -----------------------------------------------------------------------

    @abstractmethod
    def score_resolution(self, actions_taken: List[str]) -> float:
        """Score how well the agent resolved the incident.

        Returns a float in ``[0.0, 1.0]``.  Called by the grader at the end
        of an episode.
        """

    @abstractmethod
    def create_initial_state(self) -> IncidentState:
        """Create a fresh ``IncidentState`` for the start of an episode."""

    @abstractmethod
    def create_initial_observation(self) -> IncidentObservation:
        """Create the first observation (alert + system overview)."""

    # -----------------------------------------------------------------------
    # Shared helpers
    # -----------------------------------------------------------------------

    def get_investigation_result(self, target: str, command: str) -> str:
        """Return the text for an ``investigate`` action.

        Priority:
        1. Exact match in ``investigation_results`` (real data).
        2. Exact match in ``red_herrings`` (misleading-but-present data).
        3. Generic "no data" fallback.
        """
        key = (target, command)
        if key in self.investigation_results:
            return self.investigation_results[key]
        if key in self.red_herrings:
            return self.red_herrings[key]
        return f"No data available for '{command}' on '{target}'."

    def is_relevant_investigation(self, target: str, command: str) -> bool:
        """Return ``True`` if this investigation target is relevant to the
        actual root cause (used for the efficiency reward component)."""
        return (target, command) in self.relevant_investigations

    def get_system_status_dict(self) -> Dict[str, Any]:
        """Serialise all services into a dict for observation payloads."""
        return {
            name: svc.to_status_dict()
            for name, svc in self.services.items()
        }

    def apply_cascading_effects(self, time_elapsed: int) -> List[str]:
        """Apply cascading degradation based on elapsed simulated seconds.

        Each effect fires at most once (tracked via ``CascadingEffect.applied``).
        Returns human-readable descriptions of newly-applied changes so the
        environment can surface them in the next observation.
        """
        changes: List[str] = []
        for effect in self.cascading_effects:
            if effect.applied:
                continue
            if time_elapsed >= effect.time_threshold:
                svc = self.services.get(effect.service)
                if svc is None:
                    continue
                # Apply the degradation
                if effect.effect == "degraded":
                    svc.status = "degraded"
                    svc.latency_ms = max(svc.latency_ms, 2000)
                    svc.error_rate = max(svc.error_rate, 0.15)
                elif effect.effect == "down":
                    svc.status = "down"
                    svc.latency_ms = 99999
                    svc.error_rate = 1.0
                elif effect.effect == "slow":
                    svc.status = "slow"
                    svc.latency_ms = max(svc.latency_ms, 5000)
                    svc.error_rate = max(svc.error_rate, 0.05)
                else:
                    # Unknown effect type — apply as generic degradation
                    svc.status = effect.effect
                    svc.latency_ms = max(svc.latency_ms, 3000)

                effect.applied = True
                changes.append(effect.description)
        return changes

    def check_diagnosis(self, agent_diagnosis: str) -> float:
        """Score the agent's free-text diagnosis against known root-cause
        keywords.

        Returns:
            1.0  if 3+ keywords matched   (precise diagnosis)
            0.7  if 2 keywords matched     (correct but vague)
            0.4  if 1 keyword matched      (partially correct)
            0.0  if no keywords matched    (incorrect)
        """
        diagnosis_lower = agent_diagnosis.lower()
        matched = sum(1 for kw in self.root_cause_keywords if kw in diagnosis_lower)
        if matched >= 3:
            return 1.0
        if matched >= 2:
            return 0.7
        if matched == 1:
            return 0.4
        return 0.0

    def get_available_actions(self) -> List[str]:
        """Return a list of human-readable action descriptions.

        These are included in every observation so the agent knows what it
        can do next.
        """
        service_names = sorted(self.services.keys())
        svc_list = ", ".join(service_names)
        return [
            f"investigate <service> logs|metrics|deployments|dependencies|config  (services: {svc_list})",
            "investigate system overview|dependency_graph|recent_changes",
            "diagnose <service> <root-cause-description>",
            "act <service> restart|rollback|scale_up|scale_down|flush_cache|drain_connections|kill_canary",
            "escalate <team> page  (teams: backend, infrastructure, database, security, management)",
        ]

    def get_time_cost(self, action_type: str) -> int:
        """Return the simulated seconds consumed by an action type."""
        return self.time_costs.get(action_type, 10)

    def compute_time_multiplier(self, steps_taken: int) -> float:
        """Time-pressure decay multiplier for the final score.

        Linearly decays from 1.0 to 0.3 as ``steps_taken`` approaches
        ``max_steps``.  This encourages speed without making slow-but-correct
        solutions worthless.
        """
        if self.max_steps <= 0:
            return 1.0
        decay = (steps_taken / self.max_steps) * 0.7
        return max(0.3, 1.0 - decay)

    def count_cascading_damage(self) -> float:
        """Return a penalty (0.0–1.0) based on how many cascading effects
        have already fired.  Each fired effect reduces the max possible score
        by 0.05."""
        fired = sum(1 for e in self.cascading_effects if e.applied)
        return min(fired * 0.05, 1.0)

    def reset_cascading_effects(self) -> None:
        """Mark all cascading effects as unapplied — called on episode reset."""
        for effect in self.cascading_effects:
            effect.applied = False
