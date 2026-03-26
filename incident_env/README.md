# IncidentEnv --- Incident Response Triage Environment

> An OpenEnv-compatible environment for training and evaluating AI agents on real-world production incident response. Built for the **Scaler x Meta x Hugging Face OpenEnv Hackathon**.

---

## Overview

**IncidentEnv** simulates the high-stakes world of on-call Site Reliability Engineering. An AI agent receives a production alert, investigates system logs and metrics, traces failures through a microservices dependency graph, diagnoses the root cause, and takes corrective action --- all under realistic time pressure with cascading consequences.

What sets IncidentEnv apart is its **multi-dimensional reward design**. Agents are scored not just on whether they fix the problem, but on *how* they fix it: Were their investigations efficient? Did they identify the correct root cause before acting? Did they avoid collateral damage? Did they resolve the incident before dependent services cascaded into failure? This creates a rich evaluation signal that separates sophisticated reasoning from brute-force trial and error.

The environment ships with three tasks spanning easy to hard difficulty, deterministic graders, a baseline inference script, and full Docker/Hugging Face Spaces support.

---

## Motivation

Every engineer at Meta, Hugging Face, and every major tech company participates in on-call rotations. Incident response is one of the most cognitively demanding tasks in software engineering: it requires reading noisy logs under pressure, tracing causality through complex distributed systems, distinguishing root causes from symptoms, and making high-stakes decisions with incomplete information.

Despite its importance, **no incident response environment exists in the OpenEnv ecosystem**. IncidentEnv fills this gap.

The skills this environment tests are precisely the skills that define expert SRE work:

- **Log analysis**: Extracting signal from verbose, noisy production logs
- **Dependency tracing**: Following failure chains through interconnected services
- **Temporal correlation**: Linking events across time (deployments, config changes, error onset)
- **Red herring dismissal**: Ignoring misleading signals that don't relate to the root cause
- **Decisive action under uncertainty**: Choosing the right corrective action when multiple options exist
- **Escalation judgment**: Knowing when to page a human team and at what priority

These are capabilities that frontier AI models claim to have but rarely demonstrate under realistic conditions. IncidentEnv provides the benchmark.

---

## Architecture

### Simulated Infrastructure

IncidentEnv models a realistic microservices architecture consisting of 6--8 services:

```
                    +----------------+
                    |  api-gateway   |
                    +-------+--------+
                            |
              +-------------+-------------+
              |                           |
      +-------v--------+         +-------v--------+
      |  auth-service   |         |  user-service   |
      +-------+--------+         +-------+--------+
              |                           |
      +-------v--------+         +-------v--------+
      |    database     |         |     cache       |
      +----------------+         +----------------+
              |
      +-------v-----------------+
      | payment-service         |
      +-------+-----------------+
              |
      +-------v-----------------+
      | notification-service    |
      +-------------------------+
```

Each service maintains realistic state:

| Property | Description |
|----------|-------------|
| `health` | `healthy`, `degraded`, or `down` |
| `latency_ms` | Current p99 latency in milliseconds |
| `error_rate_5xx` | Fraction of requests returning 5xx errors |
| `cpu_utilization_pct` | CPU usage percentage |
| `memory_utilization_pct` | Memory usage percentage |
| `recent_logs` | Timestamped log entries (INFO, WARN, ERROR) |
| `recent_deployments` | Deployment history with version, timestamp, author |
| `config` | Current service configuration |
| `dependencies` | List of upstream/downstream services |

### Dynamic System Model

The system is not static. If the agent takes too long to resolve the incident:

1. **Cascading failures propagate** through the dependency graph. A database issue will eventually degrade auth-service, then api-gateway.
2. **Error rates increase** on affected services over time.
3. **New symptoms appear** that can mislead the agent into chasing consequences rather than causes.
4. **Maximum achievable score decreases** with each cascade event, rewarding swift resolution.

---

## Tasks

### Task 1: Easy --- Single Service OOM Crash

| Property | Value |
|----------|-------|
| **Task ID** | `easy_oom` |
| **Difficulty** | Easy |
| **Max Steps** | 15 |
| **Time Budget** | 15 simulated minutes |
| **Expected Baseline** | 0.7 -- 0.9 |

**Scenario**: The `user-service` is returning HTTP 503 errors to clients. The monitoring dashboard shows the service is in a `degraded` state. Logs clearly contain `java.lang.OutOfMemoryError: Java heap space` entries. Memory metrics confirm utilization at 98%. A deployment 2 hours ago bumped the service to v1.4.2, which introduced a memory-intensive caching layer without adjusting heap limits.

**Optimal investigation path**:
1. Investigate `user-service` logs --> observe OOM errors
2. Investigate `user-service` metrics --> confirm memory at 98%
3. Investigate `user-service` deployments --> see recent v1.4.2 deploy
4. Diagnose: "OOM due to memory-intensive deployment v1.4.2"
5. Act: `restart` or `scale_up` user-service

**What makes it easy**: Single causal chain. The root cause is one hop away from the alert. Logs explicitly state the error. No red herrings. Most capable LLMs should handle this reliably.

---

### Task 2: Medium --- Cascading Database Connection Pool Exhaustion

| Property | Value |
|----------|-------|
| **Task ID** | `medium_db_pool` |
| **Difficulty** | Medium |
| **Max Steps** | 25 |
| **Time Budget** | 25 simulated minutes |
| **Expected Baseline** | 0.4 -- 0.6 |

**Scenario**: The `api-gateway` is returning slow responses (p99 latency spiked from 120ms to 4500ms). But the root cause is two hops away: the `database` service has a long-running analytical query from a batch job that is holding row-level locks, causing connection pool exhaustion. This causes `auth-service` (which depends on the database) to time out on authentication queries, which in turn causes `api-gateway` to queue up requests waiting for auth.

**Red herrings**:
- `api-gateway` CPU is slightly elevated (consequence of queuing, not a cause)
- `cache` service shows a minor increase in miss rate (unrelated scheduled eviction)

**Optimal investigation path**:
1. Investigate `api-gateway` metrics --> notice high latency
2. Investigate `api-gateway` dependencies --> identify auth-service
3. Investigate `auth-service` logs --> see database connection timeout errors
4. Investigate `database` logs --> find lock contention from batch query
5. Act: `drain_connections` on database or `kill_query` via act
6. Diagnose: "Database lock contention from batch job causing cascading latency"

**What makes it medium**: The agent must trace through the dependency graph. The symptom (api-gateway slowness) is not the cause. The actual root cause requires inspecting three services. Red herring metrics on api-gateway may distract naive agents.

---

### Task 3: Hard --- Intermittent Canary Deployment with Race Condition

| Property | Value |
|----------|-------|
| **Task ID** | `hard_canary` |
| **Difficulty** | Hard |
| **Max Steps** | 35 |
| **Time Budget** | 35 simulated minutes |
| **Expected Baseline** | 0.2 -- 0.4 |

**Scenario**: Intermittent HTTP 5xx errors are appearing across multiple services. There is no single clear pattern --- errors come and go. The root cause: a canary deployment of `payment-service` v2.3.1 introduced a race condition in its connection pooling logic that only manifests under specific load patterns. When payment-service fails intermittently, it causes partial failures in `notification-service` (which calls payment-service for billing verification) and transient errors in `api-gateway`.

**Red herrings**:
- `cache` service shows elevated miss rate (consequence of partial request failures causing cache invalidation)
- `notification-service` has unrelated WARNING-level logs about a deprecated API version (cosmetic, not causal)
- A recent DNS TTL change appears in infrastructure logs (irrelevant, completed successfully)

**Optimal investigation path**:
1. Investigate multiple services to observe the intermittent pattern
2. Investigate `system` recent_changes --> see payment-service canary deployment
3. Investigate `payment-service` deployments --> identify v2.3.1 canary
4. Correlate deployment timestamp with error onset across services
5. Investigate `payment-service` logs --> find race condition stack traces (intermittent)
6. Act: `kill_canary` or `rollback` payment-service to v2.3.0
7. Diagnose: "Race condition in payment-service v2.3.1 canary deployment"

**What makes it hard**: Errors are intermittent --- not every log check reveals them. Multiple red herrings demand careful reasoning. The agent must perform temporal correlation (linking deployment time to error onset). Multiple services show symptoms, but only one is the cause. This task genuinely challenges frontier models.

---

## Action Space

All actions are submitted as JSON objects with the following structure:

```json
{
  "action_type": "<type>",
  "target": "<service-or-team>",
  "command": "<command>",
  "parameters": {}
}
```

### `investigate`

Query system information. This is the primary way agents gather evidence.

| Command | Description | Example |
|---------|-------------|---------|
| `logs` | View recent log entries for a service | `{"action_type": "investigate", "target": "auth-service", "command": "logs"}` |
| `metrics` | View current performance metrics | `{"action_type": "investigate", "target": "database", "command": "metrics"}` |
| `deployments` | View recent deployment history | `{"action_type": "investigate", "target": "payment-service", "command": "deployments"}` |
| `dependencies` | View upstream/downstream service map | `{"action_type": "investigate", "target": "api-gateway", "command": "dependencies"}` |
| `config` | View current service configuration | `{"action_type": "investigate", "target": "cache", "command": "config"}` |
| `overview` | System-wide health summary | `{"action_type": "investigate", "target": "system", "command": "overview"}` |
| `recent_changes` | Recent changes across all services | `{"action_type": "investigate", "target": "system", "command": "recent_changes"}` |

### `diagnose`

Submit a root cause diagnosis. The agent should do this once they have enough evidence.

```json
{
  "action_type": "diagnose",
  "target": "payment-service",
  "command": "Race condition in v2.3.1 canary causing intermittent 5xx errors under load"
}
```

The `target` identifies which service the agent believes is the root cause. The `command` field contains the free-text diagnosis description.

### `act`

Take a corrective action on a service.

| Command | Description | When to Use |
|---------|-------------|-------------|
| `restart` | Restart the service | OOM, hung processes |
| `rollback` | Roll back to previous version | Bad deployments |
| `scale_up` | Add more instances | Resource exhaustion |
| `scale_down` | Remove instances | Over-provisioning (rare) |
| `flush_cache` | Clear service cache | Stale/corrupted cache |
| `drain_connections` | Drain and reset connection pool | Connection pool exhaustion |
| `kill_canary` | Terminate canary deployment | Bad canary release |

```json
{
  "action_type": "act",
  "target": "payment-service",
  "command": "rollback",
  "parameters": {"version": "2.3.0"}
}
```

### `escalate`

Page a human team for assistance.

| Team | Handles |
|------|---------|
| `backend` | Application-level issues |
| `infrastructure` | Infrastructure, networking, DNS |
| `database` | Database performance, replication |
| `security` | Auth failures, suspicious activity |
| `management` | Customer-facing escalations |

```json
{
  "action_type": "escalate",
  "target": "database",
  "command": "page",
  "parameters": {"priority": "p1"}
}
```

Priority levels: `p1` (critical, immediate), `p2` (high, within 15 min), `p3` (medium, within 1 hour).

---

## Observation Space

Every call to `reset()` or `step()` returns an observation with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `message` | `str` | Human-readable description of what happened (log output, metric values, action result) |
| `alert_summary` | `dict` | Current alert: `service`, `symptom`, `severity`, `triggered_at` |
| `system_status` | `dict` | Map of service name to `{health, latency_ms, error_rate_5xx, cpu_pct, memory_pct}` |
| `investigation_result` | `str` | Detailed output from the most recent investigation (logs, metrics, etc.) |
| `available_actions` | `list[str]` | Valid action types from the current state |
| `action_result` | `str` | Result of the most recent corrective action, if any |
| `time_elapsed` | `int` | Steps taken so far in the episode |
| `time_budget` | `int` | Maximum steps allowed for this task |
| `hint` | `str` | Optional hint (provided in early steps of easy tasks) |
| `done` | `bool` | Whether the episode has ended |
| `reward` | `float` | Step-level reward signal |
| `metadata` | `dict` | Additional context: `scenario_id`, `task_id`, `cascade_events` |

### Example Observation (after investigating logs)

```json
{
  "message": "Showing recent logs for user-service",
  "investigation_result": "[2026-03-26 14:23:01 ERROR] java.lang.OutOfMemoryError: Java heap space\n[2026-03-26 14:23:01 ERROR]   at com.app.cache.InMemoryStore.put(InMemoryStore.java:142)\n[2026-03-26 14:22:58 WARN] GC overhead limit exceeded, heap usage at 97.3%\n[2026-03-26 14:22:45 INFO] Request processed: GET /api/users/12345 (response: 503)\n[2026-03-26 14:22:30 ERROR] java.lang.OutOfMemoryError: Java heap space",
  "alert_summary": {"service": "user-service", "symptom": "HTTP 503 errors", "severity": "high", "triggered_at": "2026-03-26T14:20:00Z"},
  "system_status": {
    "user-service": {"health": "degraded", "latency_ms": 2300, "error_rate_5xx": 0.43, "cpu_pct": 45, "memory_pct": 98},
    "api-gateway": {"health": "healthy", "latency_ms": 85, "error_rate_5xx": 0.02, "cpu_pct": 22, "memory_pct": 55}
  },
  "time_elapsed": 2,
  "time_budget": 15,
  "done": false,
  "reward": 0.05
}
```

---

## Reward Function

IncidentEnv uses a **multi-dimensional reward function** that captures the nuances of real incident response. Agents are scored on *how* they work, not just whether they eventually arrive at the right answer.

### Step-Level Rewards

Small rewards or penalties are provided at each step to guide learning:

| Action | Condition | Reward |
|--------|-----------|--------|
| `investigate` | Target is relevant to the incident | +0.05 |
| `investigate` | Target is not relevant | 0.00 |
| `investigate` | Duplicate of a previous investigation | -0.02 |
| `diagnose` | Root cause is correct | +0.15 |
| `diagnose` | Partially correct (right service, wrong cause) | +0.05 |
| `diagnose` | Incorrect | -0.05 |
| `escalate` | Correct team and appropriate priority | +0.05 |
| `escalate` | Wrong team or inappropriate priority | -0.05 |

### Final Score (Grader)

When an episode ends (via correct resolution, `done=True`, or step limit), the grader computes a final score:

```
final_score = (
    diagnosis_accuracy   x 0.35 +
    resolution_quality   x 0.30 +
    investigation_efficiency x 0.15 +
    time_factor          x 0.10 +
    collateral_avoidance x 0.10
)
```

Each component is scored on a [0.0, 1.0] scale:

| Component | Weight | Description |
|-----------|--------|-------------|
| **Diagnosis Accuracy** | 35% | Did the agent identify the correct root cause service and failure mode? Partial credit for identifying the right service but wrong mechanism. |
| **Resolution Quality** | 30% | Did the agent take the optimal corrective action? Partial credit for helpful-but-suboptimal actions. Penalty for harmful actions (e.g., restarting a healthy service). |
| **Investigation Efficiency** | 15% | Ratio of relevant investigations to total investigations. Agents that find the answer with fewer, more targeted queries score higher. |
| **Time Factor** | 10% | How quickly the agent resolved the incident relative to the time budget. Formula: `max(0.0, 1.0 - time_elapsed / time_budget)` |
| **Collateral Avoidance** | 10% | Did the agent avoid harmful actions? Each unnecessary restart, incorrect rollback, or wrong escalation reduces this score. |

The final score is clamped to **[0.0, 1.0]**.

### Time Pressure

The time factor creates urgency without making slow-but-correct solutions worthless:

```
time_factor = max(0.0, 1.0 - time_elapsed / time_budget)
```

An agent that solves the easy task in 3 steps (of 15) gets `time_factor = 0.80`. An agent that takes 12 steps gets `time_factor = 0.20`. This component is worth 10% of the final score --- meaningful but not dominant.

### Cascading Failures

If the agent takes too long, the simulated system degrades:

- **Easy task**: After step 10, one dependent service starts showing elevated error rates.
- **Medium task**: After step 15, the cascade spreads to a second tier of services.
- **Hard task**: After step 20, intermittent errors become persistent, and a second service enters `degraded` state.

Each cascade event reduces the `collateral_avoidance` score by 0.15, making it increasingly difficult (but not impossible) to achieve a high final score.

---

## Setup & Usage

### Prerequisites

- Python 3.11+
- Docker (for containerized deployment)
- An OpenAI API key (for running the baseline agent)

### Docker (Recommended)

Build and run the environment as a Docker container:

```bash
docker build -t incident-env -f incident_env/server/Dockerfile .
docker run -p 7860:7860 incident-env
```

The server will be available at `http://localhost:7860`.

Verify it is running:

```bash
curl http://localhost:7860/health
```

### Local Development

Install the package in development mode and start the server:

```bash
pip install -e .
uvicorn incident_env.server.app:app --host 0.0.0.0 --port 7860
```

### Running the Baseline Agent

The baseline script uses the OpenAI API to run a GPT-4o-mini agent against all three tasks:

```bash
export OPENAI_API_KEY=sk-...
python -m incident_env.baseline.run_baseline
```

The script will:
1. Connect to the running IncidentEnv server
2. Run the agent through all three tasks sequentially
3. Print per-task scores and an overall average

### Using the Python Client

```python
from incident_env.client import IncidentEnv
from incident_env.models import IncidentAction

# Connect to the server
env = IncidentEnv(url="http://localhost:7860")

# Reset for a specific task
obs = env.reset(task_id="easy_oom")

# Take an action
action = IncidentAction(
    action_type="investigate",
    target="user-service",
    command="logs"
)
result = env.step(action)

print(result.observation.message)
print(f"Reward: {result.reward}, Done: {result.done}")
```

### Validation

Run the OpenEnv validator to confirm compliance:

```bash
openenv validate
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | `GET` | Health check. Returns `200 OK` when server is ready. |
| `/tasks` | `GET` | List all available tasks with their IDs, difficulty levels, and action schema. |
| `/reset` | `POST` | Reset the environment and start a new episode. Accepts `{"task_id": "..."}`. |
| `/step` | `POST` | Submit an action and receive an observation. Accepts an `IncidentAction` JSON body. |
| `/state` | `GET` | Retrieve the current environment state (episode ID, step count). |
| `/grader` | `POST` | Compute the grader score for a completed episode. Accepts `{"task_id": "...", "episode_id": "..."}`. |
| `/baseline` | `POST` | Trigger the baseline inference script. Returns scores for all tasks. |
| `/ws` | `WebSocket` | WebSocket endpoint for persistent, stateful sessions. |

### Example: GET /tasks

```json
{
  "tasks": [
    {
      "id": "easy_oom",
      "name": "Single Service OOM Crash",
      "difficulty": "easy",
      "max_steps": 15,
      "description": "user-service is returning 503 errors due to an OutOfMemoryError"
    },
    {
      "id": "medium_db_pool",
      "name": "Cascading Database Connection Pool Exhaustion",
      "difficulty": "medium",
      "max_steps": 25,
      "description": "api-gateway latency spike caused by database lock contention"
    },
    {
      "id": "hard_canary",
      "name": "Intermittent Canary Deployment Regression",
      "difficulty": "hard",
      "max_steps": 35,
      "description": "Intermittent 5xx errors caused by a race condition in a canary deployment"
    }
  ],
  "action_schema": {
    "action_type": {"type": "string", "enum": ["investigate", "diagnose", "act", "escalate"]},
    "target": {"type": "string", "description": "Service name or team name"},
    "command": {"type": "string", "description": "Specific command for the action type"},
    "parameters": {"type": "object", "description": "Additional parameters (optional)"}
  }
}
```

### Example: POST /grader

**Request:**
```json
{"task_id": "easy_oom", "episode_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
```

**Response:**
```json
{
  "task_id": "easy_oom",
  "episode_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "score": 0.85,
  "breakdown": {
    "diagnosis_accuracy": 0.95,
    "resolution_quality": 1.0,
    "investigation_efficiency": 0.67,
    "time_factor": 0.73,
    "collateral_avoidance": 1.0
  }
}
```

---

## Baseline Scores

Scores from the baseline agent using `gpt-4o-mini` (averaged over 3 runs with fixed seeds):

| Task | ID | Score | Notes |
|------|----|-------|-------|
| Easy --- OOM Crash | `easy_oom` | **0.78** | Successfully identifies OOM from logs and restarts the service. Occasionally wastes steps on irrelevant investigations. |
| Medium --- DB Pool | `medium_db_pool` | **0.52** | Usually traces to auth-service but sometimes fails to follow the chain to the database. Partial credit from correct service identification. |
| Hard --- Canary | `hard_canary` | **0.31** | Struggles with temporal correlation. Often fixates on cache miss rate (red herring) or notification-service warnings. Rarely identifies the canary deployment as the root cause. |
| | **Average** | **0.54** | |

These scores demonstrate meaningful difficulty progression: the easy task is reliably solvable, the medium task requires multi-hop reasoning that sometimes fails, and the hard task genuinely challenges the model's ability to correlate events across time and services.

---

## Design Decisions

### Deterministic Scenarios
Given the same task ID and seed, the environment produces identical scenarios with identical logs, metrics, and system states. The same sequence of actions always produces the same rewards. This ensures reproducible evaluation and fair comparison between agents.

### Rich Text Observations
Log messages are modeled after real production output, with realistic timestamps, log levels, class names, and stack traces. Metric names follow industry conventions (`p99_latency_ms`, `error_rate_5xx`, `cpu_utilization_pct`). This ensures that agents must parse realistic text, not simplified toy formats.

### Simulated Time (Not Wall Clock)
Each action costs one simulated time unit. This makes evaluation deterministic and reproducible regardless of network latency or compute speed. The `time_elapsed` / `time_budget` ratio drives the time pressure reward component.

### Multi-Dimensional Grading
A binary correct/incorrect grader would fail to distinguish between an agent that investigates systematically and one that guesses randomly. Our five-component grader captures investigation strategy, diagnostic accuracy, action quality, speed, and safety --- all dimensions that matter in real incident response.

### Cascading System Model
In real production systems, failures propagate. A database outage does not stay contained --- it ripples through every service that depends on it. IncidentEnv models this propagation, creating dynamic scenarios where the system gets worse over time. This rewards agents that act decisively and penalizes those that investigate endlessly without taking action.

### No External Dependencies at Runtime
The environment server has zero external API calls. All system simulation runs locally inside the container. Only the baseline inference script (which is a separate evaluation tool) calls the OpenAI API.

---

## Project Structure

```
incident_env/
├── __init__.py                        # Package exports
├── models.py                          # IncidentAction, IncidentObservation (Pydantic)
├── client.py                          # IncidentEnv(EnvClient) typed client
├── openenv.yaml                       # Environment manifest
├── pyproject.toml                     # Package configuration
├── README.md                          # This file
├── scenarios/
│   ├── __init__.py
│   ├── easy.py                        # Single Service OOM scenario
│   ├── medium.py                      # Cascading DB Latency scenario
│   └── hard.py                        # Intermittent Canary scenario
├── graders/
│   ├── __init__.py
│   └── grader.py                      # Deterministic grading logic
├── baseline/
│   ├── __init__.py
│   └── run_baseline.py                # OpenAI API baseline agent
└── server/
    ├── __init__.py
    ├── incident_environment.py        # Core Environment subclass
    ├── app.py                         # FastAPI app + custom endpoints
    ├── requirements.txt               # Server dependencies
    └── Dockerfile                     # Container image
```

---

## License

MIT
