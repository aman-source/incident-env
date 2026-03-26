"""
FastAPI application for the Incident Response Triage Environment.

Exposes the IncidentEnvironment over HTTP and WebSocket endpoints,
plus hackathon-required custom endpoints: /tasks, /grader, /baseline.

Usage:
    uvicorn incident_env.server.app:app --host 0.0.0.0 --port 7860
"""

from __future__ import annotations

try:
    from openenv.core.env_server.http_server import create_fastapi_app
except Exception as e:
    raise ImportError(
        "openenv-core is required. Install with: pip install openenv-core"
    ) from e

try:
    from incident_env.models import IncidentAction, IncidentObservation
    from incident_env.server.incident_environment import IncidentEnvironment
except ModuleNotFoundError:
    from models import IncidentAction, IncidentObservation
    from server.incident_environment import IncidentEnvironment


# create_fastapi_app — lighter than create_app (no Gradio UI), faster startup
app = create_fastapi_app(
    IncidentEnvironment,
    IncidentAction,
    IncidentObservation,
    max_concurrent_envs=5,
)


# ---------------------------------------------------------------------------
# Root endpoint — required for HuggingFace Spaces to show "Running"
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Root endpoint with environment info."""
    return {
        "name": "IncidentEnv",
        "description": "Incident Response Triage Environment for OpenEnv",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "tasks": "/tasks",
            "reset": "POST /reset",
            "step": "POST /step",
            "state": "/state",
            "grader": "POST /grader",
            "baseline": "POST /baseline",
            "docs": "/docs",
            "websocket": "/ws",
        },
    }


# ---------------------------------------------------------------------------
# Custom hackathon endpoints
# ---------------------------------------------------------------------------

@app.get("/tasks")
async def get_tasks():
    """Return list of tasks and action schema."""
    return {
        "tasks": [
            {
                "id": "easy_oom",
                "name": "Single Service OOM Crash",
                "difficulty": "easy",
                "max_steps": 15,
                "time_budget": 300,
                "description": "A single service is crashing due to an out-of-memory error after a recent deployment.",
            },
            {
                "id": "medium_db_pool",
                "name": "Cascading Database Connection Pool Exhaustion",
                "difficulty": "medium",
                "max_steps": 25,
                "time_budget": 240,
                "description": "Multiple services degraded. Root cause is a connection leak in one service exhausting the shared database pool.",
            },
            {
                "id": "hard_canary",
                "name": "Intermittent Canary Deployment Failure",
                "difficulty": "hard",
                "max_steps": 35,
                "time_budget": 180,
                "description": "Intermittent errors affecting ~10% of requests. Requires correlating canary deployment with provider-specific token failures.",
            },
        ],
        "action_schema": {
            "action_type": {
                "type": "string",
                "enum": ["investigate", "diagnose", "act", "escalate"],
                "description": "The type of action to take",
            },
            "target": {
                "type": "string",
                "description": "Service or component to target (e.g. 'api-gateway', 'database')",
            },
            "command": {
                "type": "string",
                "description": "Specific command (e.g. 'logs', 'restart', 'rollback')",
            },
            "parameters": {
                "type": "object",
                "description": "Additional parameters (e.g. {version: 'previous'} for rollback)",
            },
        },
    }


@app.post("/grader")
async def run_grader():
    """Return grader score for the current episode.

    Uses a temporary environment instance. In a real multi-session setup,
    the per-session env would be accessed via the WebSocket session.
    """
    env = IncidentEnvironment()
    return env.compute_grader_score()


@app.post("/baseline")
async def run_baseline():
    """Trigger baseline inference and return scores for all 3 tasks."""
    try:
        from incident_env.baseline.run_baseline import run_all_baselines
    except ModuleNotFoundError:
        from baseline.run_baseline import run_all_baselines
    return await run_all_baselines()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(host: str = "0.0.0.0", port: int = 7860):
    """Run the server directly."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7860)
    args = parser.parse_args()
    main(port=args.port)
