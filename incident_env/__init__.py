"""Incident Response Triage Environment for OpenEnv."""

# Lazy imports to keep startup fast
__all__ = [
    "IncidentAction",
    "IncidentObservation",
    "IncidentState",
    "IncidentEnv",
]


def __getattr__(name):
    if name in ("IncidentAction", "IncidentObservation", "IncidentState"):
        from incident_env.models import IncidentAction, IncidentObservation, IncidentState
        return locals()[name]
    if name == "IncidentEnv":
        from incident_env.client import IncidentEnv
        return IncidentEnv
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
