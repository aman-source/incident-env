"""
Baseline inference script for the Incident Response Environment.

Uses OpenAI API to run an LLM agent against all 3 tasks and produce
reproducible scores. Reads OPENAI_API_KEY from environment variables.

Usage:
    OPENAI_API_KEY=sk-... python -m incident_env.baseline.run_baseline
"""

from __future__ import annotations

import json
import os
from typing import Any

from incident_env.models import IncidentAction, IncidentObservation
from incident_env.server.incident_environment import IncidentEnvironment

SYSTEM_PROMPT = """You are an expert SRE (Site Reliability Engineer) responding to a production incident.
You will receive observations about the system state and must take actions to diagnose and resolve the incident as quickly as possible.

Available action types:
1. investigate - Check logs, metrics, deployments, dependencies, or config of a service
   Example: {"action_type": "investigate", "target": "api-gateway", "command": "logs"}
   Valid commands: logs, metrics, deployments, dependencies, config
   For system-wide info: {"action_type": "investigate", "target": "system", "command": "overview"}

2. diagnose - Submit your root cause diagnosis
   Example: {"action_type": "diagnose", "target": "api-gateway", "command": "Memory leak in v2.4.1 causing OOM"}

3. act - Take corrective action
   Example: {"action_type": "act", "target": "api-gateway", "command": "rollback", "parameters": {"version": "previous"}}
   Valid commands: restart, rollback, scale_up, scale_down, flush_cache, drain_connections, kill_canary

4. escalate - Page a team
   Example: {"action_type": "escalate", "target": "infrastructure", "command": "page", "parameters": {"priority": "p1"}}

Strategy:
- Start by investigating the services mentioned in the alert
- Check logs first, then metrics, then deployment history
- Look for correlations between deployment times and incident start
- Diagnose before acting
- Take the most targeted corrective action possible

IMPORTANT: Respond with ONLY a valid JSON action object. No explanation, no markdown, just JSON."""


def _parse_action(text: str) -> IncidentAction:
    """Parse LLM response into an IncidentAction."""
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fallback: try to extract JSON from the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(text[start:end])
        else:
            # Default action
            return IncidentAction(
                action_type="investigate",
                target="system",
                command="overview",
            )

    return IncidentAction(
        action_type=data.get("action_type", "investigate"),
        target=data.get("target", "system"),
        command=data.get("command", "overview"),
        parameters=data.get("parameters", {}),
    )


def _observation_to_text(obs: IncidentObservation) -> str:
    """Convert observation to text for the LLM."""
    parts = []

    if obs.message:
        parts.append(f"MESSAGE: {obs.message}")
    if obs.alert_summary:
        parts.append(f"ALERT: {obs.alert_summary}")
    if obs.investigation_result:
        parts.append(f"INVESTIGATION RESULT:\n{obs.investigation_result}")
    if obs.action_result:
        parts.append(f"ACTION RESULT: {obs.action_result}")
    if obs.system_status:
        status_lines = []
        for svc, info in obs.system_status.items():
            if isinstance(info, dict):
                status_lines.append(
                    f"  {svc}: status={info.get('status', '?')} "
                    f"latency={info.get('latency_ms', '?')}ms "
                    f"errors={info.get('error_rate', '?')}"
                )
        if status_lines:
            parts.append("SYSTEM STATUS:\n" + "\n".join(status_lines))

    parts.append(f"TIME: {obs.time_elapsed}s / {obs.time_budget}s budget")

    if obs.hint:
        parts.append(f"HINT: {obs.hint}")

    return "\n\n".join(parts)


def run_single_task(
    env: IncidentEnvironment,
    task_id: str,
    client: Any | None = None,
    model: str = "gpt-4o-mini",
    max_agent_steps: int = 20,
) -> dict:
    """Run baseline agent on a single task. Returns grader result."""

    obs = env.reset(task_id=task_id)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.append({"role": "user", "content": _observation_to_text(obs)})

    for step_num in range(max_agent_steps):
        if obs.done:
            break

        if client is not None:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.0,
                max_tokens=256,
            )
            assistant_text = response.choices[0].message.content
        else:
            # No API key — use a scripted fallback for testing
            assistant_text = _scripted_action(task_id, step_num)

        messages.append({"role": "assistant", "content": assistant_text})

        try:
            action = _parse_action(assistant_text)
        except Exception:
            action = IncidentAction(
                action_type="investigate", target="system", command="overview"
            )

        obs = env.step(action)
        messages.append({"role": "user", "content": _observation_to_text(obs)})

    # Get final grader score
    return env.compute_grader_score()


def _scripted_action(task_id: str, step: int) -> str:
    """Scripted fallback actions when no API key is available."""
    scripts = {
        "easy_oom": [
            '{"action_type": "investigate", "target": "api-gateway", "command": "logs"}',
            '{"action_type": "investigate", "target": "api-gateway", "command": "metrics"}',
            '{"action_type": "investigate", "target": "api-gateway", "command": "deployments"}',
            '{"action_type": "diagnose", "target": "api-gateway", "command": "Memory leak in api-gateway v2.4.1 causing OOM from unbounded request body cache"}',
            '{"action_type": "act", "target": "api-gateway", "command": "rollback", "parameters": {"version": "v2.4.0"}}',
        ],
        "medium_db_pool": [
            '{"action_type": "investigate", "target": "payment-service", "command": "logs"}',
            '{"action_type": "investigate", "target": "database", "command": "logs"}',
            '{"action_type": "investigate", "target": "user-service", "command": "logs"}',
            '{"action_type": "investigate", "target": "user-service", "command": "deployments"}',
            '{"action_type": "investigate", "target": "system", "command": "recent_changes"}',
            '{"action_type": "diagnose", "target": "user-service", "command": "Connection leak in user-service v3.2.0 bulk sync batch processing exhausting shared DB connection pool"}',
            '{"action_type": "act", "target": "user-service", "command": "restart"}',
        ],
        "hard_canary": [
            '{"action_type": "investigate", "target": "auth-service", "command": "logs"}',
            '{"action_type": "investigate", "target": "auth-service", "command": "metrics"}',
            '{"action_type": "investigate", "target": "auth-service", "command": "deployments"}',
            '{"action_type": "investigate", "target": "auth-service", "command": "config"}',
            '{"action_type": "investigate", "target": "system", "command": "recent_changes"}',
            '{"action_type": "diagnose", "target": "auth-service", "command": "Canary v5.1.0 claims-validator rejects provider-b nested_permissions in realm_access"}',
            '{"action_type": "act", "target": "auth-service", "command": "kill_canary"}',
        ],
    }
    task_script = scripts.get(task_id, scripts["easy_oom"])
    idx = min(step, len(task_script) - 1)
    return task_script[idx]


async def run_all_baselines() -> dict:
    """Run baseline against all tasks. Returns summary with scores."""

    api_key = os.environ.get("OPENAI_API_KEY")
    client = None
    model = "gpt-4o-mini"

    if api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
        except ImportError:
            client = None

    env = IncidentEnvironment()
    task_ids = ["easy_oom", "medium_db_pool", "hard_canary"]
    scores = {}

    for task_id in task_ids:
        result = run_single_task(env, task_id, client=client, model=model)
        scores[task_id] = result.get("score", 0.0)

    avg = sum(scores.values()) / len(scores) if scores else 0.0

    return {
        "model": model if client else "scripted-fallback",
        "scores": scores,
        "average": round(avg, 4),
    }


if __name__ == "__main__":
    import asyncio

    async def main():
        result = await run_all_baselines()
        print(json.dumps(result, indent=2))

    asyncio.run(main())
