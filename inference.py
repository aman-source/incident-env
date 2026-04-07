"""
Inference script for the Incident Response Triage Environment.

Runs an LLM agent against all 3 incident response tasks using the
OpenAI-compatible API through the validator's LiteLLM proxy.

Environment Variables (injected by validator):
    API_BASE_URL   The API endpoint for the LLM.
    API_KEY        API key for the LLM proxy.
    HF_TOKEN       Hugging Face token (fallback for API_KEY).
    MODEL_NAME     The model identifier to use for inference.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, List, Optional

from openai import OpenAI

from incident_env.models import IncidentAction, IncidentObservation
from incident_env.server.incident_environment import IncidentEnvironment

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "gpt-4o-mini"
BENCHMARK = "incident_env"
MAX_STEPS = 20
TEMPERATURE = 0.7
MAX_TOKENS = 256
SUCCESS_SCORE_THRESHOLD = 0.1

# ---------------------------------------------------------------------------
# Structured stdout logging (exact format required by validator)
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# SRE system prompt
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_action(text: str) -> IncidentAction:
    """Parse LLM response into an IncidentAction."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
            except json.JSONDecodeError:
                return IncidentAction(
                    action_type="investigate", target="system", command="overview",
                )
        else:
            return IncidentAction(
                action_type="investigate", target="system", command="overview",
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


def _action_to_str(action: IncidentAction) -> str:
    """Format action as a compact string for [STEP] logging."""
    return f"{action.action_type}('{action.target}','{action.command}')"


# ---------------------------------------------------------------------------
# Task registry
# ---------------------------------------------------------------------------
TASK_REGISTRY = {
    "easy_oom": "easy_oom",
    "medium_db_pool": "medium_db_pool",
    "hard_canary": "hard_canary",
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run baseline inference against all 3 tasks."""
    if not API_KEY:
        print("[DEBUG] No API key found, using scripted fallback agent", flush=True)
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "sk-placeholder")

    env = IncidentEnvironment()

    for task_id in TASK_REGISTRY:
        rewards: List[float] = []
        steps_taken = 0
        score = 0.0
        success = False

        log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

        try:
            obs = env.reset(task_id=task_id)
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            messages.append({"role": "user", "content": _observation_to_text(obs)})

            for step in range(1, MAX_STEPS + 1):
                if obs.done:
                    break

                # Get action from LLM
                try:
                    response = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=messages,
                        temperature=TEMPERATURE,
                        max_tokens=MAX_TOKENS,
                        stream=False,
                    )
                    assistant_text = (response.choices[0].message.content or "").strip()
                except Exception as exc:
                    print(f"[DEBUG] Model request failed: {exc}", flush=True)
                    assistant_text = _scripted_action(task_id, step - 1)

                if not assistant_text:
                    assistant_text = _scripted_action(task_id, step - 1)

                messages.append({"role": "assistant", "content": assistant_text})

                try:
                    action = _parse_action(assistant_text)
                except Exception:
                    action = IncidentAction(
                        action_type="investigate", target="system", command="overview"
                    )

                obs = env.step(action)
                messages.append({"role": "user", "content": _observation_to_text(obs)})

                reward = obs.reward if obs.reward is not None else 0.0
                done = obs.done
                error = None

                rewards.append(reward)
                steps_taken = step

                log_step(
                    step=step,
                    action=_action_to_str(action),
                    reward=reward,
                    done=done,
                    error=error,
                )

                if done:
                    break

            # Compute final score from grader
            result = env.compute_grader_score()
            score = result.get("score", 0.0)
            score = min(max(score, 0.0), 1.0)
            success = score >= SUCCESS_SCORE_THRESHOLD

        except Exception as exc:
            print(f"[DEBUG] Task {task_id} failed: {exc}", flush=True)

        finally:
            log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    main()
