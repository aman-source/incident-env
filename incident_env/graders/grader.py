"""
Deterministic grading logic for the Incident Response Environment.

Scores agent performance on a 0.0-1.0 scale across five dimensions:
  - Diagnosis accuracy (35%)
  - Resolution quality (30%)
  - Investigation efficiency (15%)
  - Time factor (10%)
  - Collateral avoidance (10%)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from incident_env.models import IncidentState
    from incident_env.scenarios.base import BaseScenario


def grade_episode(state: "IncidentState", scenario: "BaseScenario") -> dict:
    """Grade a completed episode.

    Returns a dict with ``score`` (float 0.0-1.0) and ``breakdown``.
    """

    # 1. Diagnosis accuracy (0.35)
    if state.agent_diagnosis:
        diagnosis_score = scenario.check_diagnosis(state.agent_diagnosis)
    else:
        diagnosis_score = 0.0

    # 2. Resolution quality (0.30)
    resolution_score = scenario.score_resolution(state.agent_actions_taken)

    # 3. Investigation efficiency (0.15)
    if state.total_investigations > 0:
        efficiency_score = state.correct_investigations / state.total_investigations
    else:
        efficiency_score = 0.0

    # 4. Time factor (0.10) — reward for speed
    time_score = max(0.0, 1.0 - (state.time_elapsed / max(state.time_budget, 1)))

    # 5. Collateral factor (0.10) — penalise harmful actions
    collateral_score = max(0.0, 1.0 - state.collateral_damage)

    final = (
        diagnosis_score * 0.35
        + resolution_score * 0.30
        + efficiency_score * 0.15
        + time_score * 0.10
        + collateral_score * 0.10
    )
    final = round(min(1.0, max(0.0, final)), 4)

    return {
        "score": final,
        "breakdown": {
            "diagnosis_accuracy": round(diagnosis_score, 4),
            "resolution_quality": round(resolution_score, 4),
            "investigation_efficiency": round(efficiency_score, 4),
            "time_factor": round(time_score, 4),
            "collateral_avoidance": round(collateral_score, 4),
        },
    }
