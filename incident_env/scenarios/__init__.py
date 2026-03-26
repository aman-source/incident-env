"""Incident scenario definitions."""

__all__ = ["EasyOOMScenario", "MediumDBPoolScenario", "HardCanaryScenario"]


def __getattr__(name):
    if name == "EasyOOMScenario":
        from incident_env.scenarios.easy import EasyOOMScenario
        return EasyOOMScenario
    if name == "MediumDBPoolScenario":
        from incident_env.scenarios.medium import MediumDBPoolScenario
        return MediumDBPoolScenario
    if name == "HardCanaryScenario":
        from incident_env.scenarios.hard import HardCanaryScenario
        return HardCanaryScenario
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
