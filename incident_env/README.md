---
title: IncidentEnv
emoji: 🚨
colorFrom: red
colorTo: yellow
sdk: docker
pinned: false
app_port: 7860
---

# IncidentEnv -- Incident Response Triage Environment

An **OpenEnv-compatible environment** that simulates production incident response for training and evaluating AI agents. The agent takes on the role of an on-call SRE engineer: receiving alerts, investigating logs and metrics across a microservices architecture, tracing failures through dependency graphs, diagnosing root causes, and executing corrective actions -- all under realistic time pressure with cascading system degradation. IncidentEnv features a novel multi-dimensional reward function incorporating time-decay scoring, cascading failure penalties, investigation efficiency tracking, and blast-radius-aware collateral damage scoring, producing evaluation signals that sharply distinguish sophisticated reasoning from brute-force exploration.

Built for the **Scaler x Meta x Hugging Face OpenEnv Hackathon** (India edition, 70K+ participants).

---

## Why Incident Response?

Incident response is one of the most cognitively demanding tasks in software engineering -- and one that every engineer at Meta, Hugging Face, and every major tech company performs during on-call rotations. Despite its centrality to production reliability, **no incident response environment exists in the OpenEnv ecosystem**. IncidentEnv fills this gap.

The skills this environment evaluates are precisely those that define expert SRE work:

- **Log analysis** -- Extracting signal from verbose, noisy production logs with realistic timestamps, stack traces, and interleaved entries
- **Dependency tracing** -- Following failure chains through interconnected services where the symptom is multiple hops from the root cause
- **Temporal correlation** -- Linking events across time (deployments, config changes, error onset windows) to identify causality
- **Red herring dismissal** -- Ignoring misleading signals (elevated CPU from queuing, unrelated warning logs, cosmetic config changes) that do not relate to the root cause
- **Decisive action under uncertainty** -- Choosing the correct corrective action when multiple options exist, each with different blast radius
- **Escalation judgment** -- Knowing when to page a human team and at what priority level

The reward design is genuinely novel. Unlike binary pass/fail graders, IncidentEnv scores agents across five orthogonal dimensions with time-pressure decay, cascading failure state changes, and minimum-investigation gates that prevent lucky guessing. This creates evaluation signals that frontier models find genuinely challenging -- even 70B parameter models score only 0.72 on the hard task.

---

## Tasks

| Task | ID | Difficulty | Services | Max Steps | Time Budget | What It Tests |
|------|----|------------|----------|-----------|-------------|---------------|
| Single Service OOM Crash | `easy_oom` | Easy | 5 | 15 | 100s | Log reading, single-hop diagnosis, basic corrective action |
| Cascading DB Connection Pool Exhaustion | `medium_db_pool` | Medium | 9 | 15 | 100s | Multi-hop dependency tracing, red herring dismissal, connection pool reasoning |
| Intermittent Canary Deployment + OAuth Provider Failures | `hard_canary` | Hard | 15 | 15 | 100s | Temporal correlation, intermittent error analysis, canary identification, multi-layer red herrings |

---

### Task 1: Easy -- Single Service OOM Crash

**Scenario**: The `user-service` is returning HTTP 503 errors. Logs clearly show `java.lang.OutOfMemoryError: Java heap space` entries with stack traces pointing to `InMemoryStore.put()`. Memory metrics confirm utilization at 98%. A deployment of v2.4.1 two hours ago introduced a memory-intensive in-memory caching layer without adjusting heap limits.

**What the agent must do**:
1. Investigate `user-service` logs -- observe OOM errors with heap exhaustion
2. Investigate `user-service` metrics -- confirm memory at 98%, correlate with deployment
3. Investigate `user-service` deployments -- identify v2.4.1 as the triggering change
4. Diagnose: "OOM caused by memory-intensive deployment v2.4.1"
5. Act: `rollback` user-service to previous version

**What makes it easy**: Single causal chain with one service. The root cause is one hop from the alert. Logs explicitly state the error. No red herrings. This task validates that the agent can read logs, correlate with deployment history, and take basic corrective action.

---

### Task 2: Medium -- Cascading DB Connection Pool Exhaustion

**Scenario**: The `payment-service` is timing out on transaction processing. But the root cause is two hops away: the `user-service` has a connection pool leak due to unclosed database connections in its user lookup path. This exhausts the shared `database` connection pool, which then causes `payment-service` (which also depends on the database) to fail on transaction commits.

**Red herrings**:
- Yesterday's `payment-service` deployment (v3.1.0) -- looks suspicious but is unrelated
- A DNS resolution blip in infrastructure logs -- resolved automatically, no impact
- `api-gateway` latency elevation -- consequence of downstream failures, not a cause

**What the agent must do**: Trace from payment-service symptoms through database connection exhaustion to user-service as the leak source. Requires minimum 4 investigations to build the causal chain. The agent must resist the temptation to blame payment-service's recent deployment and instead follow the connection pool evidence to user-service.

**What makes it medium**: Root cause is 2 hops from the presenting symptom. Multiple services show degradation. Two distinct red herrings compete for the agent's attention. Requires understanding connection pool mechanics and dependency ordering.

---

### Task 3: Hard -- Intermittent Canary Deployment with OAuth Provider Failures

**Scenario**: Intermittent HTTP 5xx errors (~10% of requests) appear across multiple services with no clear pattern. The root cause: a canary deployment of `auth-service` v2.1.0-canary introduced a claims-validator bug that fails only when processing tokens from OAuth provider-B (provider-A tokens work fine). Since only the canary pod is affected and only provider-B tokens trigger the bug, errors are sparse and intermittent.

**Red herrings** (4 layers):
- `recommendation-service` CPU spike -- legitimate but unrelated batch processing
- `config-service` recent updates -- routine config rotation, no functional impact
- `database` slow query log -- occasional long-running analytics query, pre-existing
- Certificate renewal activity in infrastructure -- completed successfully, no errors

**What makes it hard**:
- **Intermittent signals**: First log check shows mostly clean output -- only 2 buried error lines among 30+ successful requests. Errors appear only ~30% of the time on any given check.
- **15 services**: Large search space with many potential suspects
- **Canary specificity**: Must identify that only the canary pod (not the full deployment) is the issue
- **Provider correlation**: Must notice the provider-B pattern in the sparse error messages
- **Time pressure**: 100-second budget with max 15 steps means every investigation must count

---

## Benchmark Results

Scores from running the baseline agent across all three tasks:

| Model | Easy | Medium | Hard | Average |
|-------|------|--------|------|---------|
| **Llama 3.3 70B Instruct** | 0.95 | 0.76 | 0.72 | **0.81** |
| **Llama 4 Scout 17B** | 0.96 | 0.70 | 0.20 | **0.62** |
| **Llama 3.1 8B Instruct** | 0.86 | 0.70 | 0.53 | **0.70** |

**Key observations**:
- The easy task is reliably solvable by all model sizes, validating it as a reasonable baseline.
- The medium task shows consistent performance around 0.70-0.76, with differentiation coming from investigation efficiency and time factor.
- The hard task **genuinely challenges all models**. Even Llama 3.3 70B scores only 0.72, while Scout 17B drops to 0.20 -- struggling with temporal correlation and intermittent error patterns. Notably, 8B outperforms Scout 17B on the hard task (0.53 vs 0.20), suggesting that the task tests reasoning depth rather than raw parameter count.
- The spread between easy and hard scores (0.95 to 0.72 for 70B, 0.96 to 0.20 for Scout) demonstrates meaningful difficulty progression.

---

## Action Space

All actions are submitted as JSON objects with four fields:

```json
{
  "action_type": "<type>",
  "target": "<service-or-team>",
  "command": "<command>",
  "parameters": {}
}
```

### `investigate` -- Query system information

| Command | Description | Example |
|---------|-------------|---------|
| `logs` | View recent log entries for a service | `{"action_type": "investigate", "target": "auth-service", "command": "logs"}` |
| `metrics` | View current performance metrics | `{"action_type": "investigate", "target": "database", "command": "metrics"}` |
| `deployments` | View recent deployment history | `{"action_type": "investigate", "target": "payment-service", "command": "deployments"}` |
| `dependencies` | View upstream/downstream service map | `{"action_type": "investigate", "target": "api-gateway", "command": "dependencies"}` |
| `config` | View current service configuration | `{"action_type": "investigate", "target": "cache", "command": "config"}` |
| `overview` | System-wide health summary | `{"action_type": "investigate", "target": "system", "command": "overview"}` |
| `recent_changes` | Recent changes across all services | `{"action_type": "investigate", "target": "system", "command": "recent_changes"}` |

### `diagnose` -- Submit root cause diagnosis

```json
{
  "action_type": "diagnose",
  "target": "auth-service",
  "command": "Claims-validator bug in v2.1.0-canary causing provider-B OAuth token failures"
}
```

The `target` identifies which service the agent believes is the root cause. The `command` field contains the free-text diagnosis. The grader uses keyword matching against the expected root cause to score diagnosis accuracy.

### `act` -- Take corrective action

| Command | Description | When to Use |
|---------|-------------|-------------|
| `restart` | Restart the service | OOM, hung processes |
| `rollback` | Roll back to previous version | Bad deployments |
| `scale_up` | Add more instances | Resource exhaustion |
| `scale_down` | Remove instances | Over-provisioning |
| `flush_cache` | Clear service cache | Stale/corrupted cache |
| `drain_connections` | Drain and reset connection pool | Connection pool exhaustion |
| `kill_canary` | Terminate canary deployment | Bad canary release |

```json
{
  "action_type": "act",
  "target": "auth-service",
  "command": "kill_canary",
  "parameters": {}
}
```

### `escalate` -- Page a human team

| Team | Handles |
|------|---------|
| `backend` | Application-level issues |
| `infrastructure` | Infrastructure, networking, DNS |
| `database` | Database performance, replication, connection pools |
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

Priority levels: `p1` (critical, immediate response), `p2` (high, within 15 minutes), `p3` (medium, within 1 hour).

---

## Observation Space

Every call to `reset()` or `step()` returns an observation with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `message` | `str` | Human-readable description of the current state or action result |
| `alert_summary` | `dict` | Current alert details: `service`, `symptom`, `severity`, `triggered_at` |
| `system_status` | `dict` | Map of service name to `{health, latency_ms, error_rate_5xx, cpu_pct, memory_pct}` |
| `investigation_result` | `str` | Detailed output from the most recent investigation (logs, metrics, deployment history) |
| `available_actions` | `list[str]` | Valid action types from the current state |
| `action_result` | `str` | Result of the most recent corrective action, if any |
| `time_elapsed` | `int` | Simulated seconds elapsed in the episode |
| `time_budget` | `int` | Maximum simulated seconds for this task |
| `hint` | `str` | Optional hint (provided in early steps of easy tasks) |
| `done` | `bool` | Whether the episode has ended |
| `reward` | `float` | Step-level reward signal |
| `metadata` | `dict` | Additional context: `scenario_id`, `task_id`, `cascade_events`, `steps_taken` |

### Example Observation (after investigating logs)

```json
{
  "message": "Showing recent logs for user-service",
  "investigation_result": "[2026-03-26 14:23:01 ERROR] java.lang.OutOfMemoryError: Java heap space\n[2026-03-26 14:23:01 ERROR]   at com.app.cache.InMemoryStore.put(InMemoryStore.java:142)\n[2026-03-26 14:22:58 WARN] GC overhead limit exceeded, heap usage at 97.3%\n[2026-03-26 14:22:45 INFO] Request processed: GET /api/users/12345 (response: 503)\n[2026-03-26 14:22:30 ERROR] java.lang.OutOfMemoryError: Java heap space",
  "alert_summary": {
    "service": "user-service",
    "symptom": "HTTP 503 errors",
    "severity": "high",
    "triggered_at": "2026-03-26T14:20:00Z"
  },
  "system_status": {
    "user-service": {"health": "degraded", "latency_ms": 2300, "error_rate_5xx": 0.43, "cpu_pct": 45, "memory_pct": 98},
    "api-gateway": {"health": "healthy", "latency_ms": 85, "error_rate_5xx": 0.02, "cpu_pct": 22, "memory_pct": 55}
  },
  "time_elapsed": 12,
  "time_budget": 100,
  "done": false,
  "reward": 0.05
}
```

---

## Reward Function

IncidentEnv uses a **multi-dimensional reward function** that captures the nuances of real incident response. Agents are scored on *how* they investigate, diagnose, and act -- not just whether they eventually stumble upon the answer.

### Step-Level Rewards

Small rewards or penalties at each step guide the agent and provide a learning signal:

| Action | Condition | Reward |
|--------|-----------|--------|
| `investigate` | Target is relevant to the incident chain | +0.05 |
| `investigate` | Target is irrelevant (healthy, unrelated service) | 0.00 |
| `investigate` | Duplicate of a previous investigation | -0.02 |
| `diagnose` | Correct root cause (3+ matching keywords) | +0.10 |
| `diagnose` | Partially correct (right service or partial keywords) | +0.05 |
| `diagnose` | Incorrect | -0.05 |
| `diagnose` | Submitted before minimum investigations met | Rejected (not scored) |
| `act` | Correct corrective action on correct service | +0.10 |
| `act` | Wrong action or wrong target | -0.05 |
| `escalate` | Correct team and appropriate priority | +0.05 |
| `escalate` | Wrong team or inappropriate priority | -0.05 |

### Final Score (Grader)

When an episode completes, the deterministic grader computes a weighted final score:

```
final_score = (
    diagnosis_accuracy     * 0.30 +
    resolution_quality     * 0.25 +
    investigation_efficiency * 0.20 +
    time_factor            * 0.15 +
    collateral_avoidance   * 0.10
)
```

Each component is scored on a [0.0, 1.0] scale:

| Component | Weight | Scoring Logic |
|-----------|--------|---------------|
| **Diagnosis Accuracy** | 30% | 0.0 = no diagnosis, 0.4 = correct service only, 0.7 = partial keyword match (1-2 keywords), 1.0 = full match (3+ keywords against expected root cause) |
| **Resolution Quality** | 25% | 1.0 = optimal action on correct service, 0.5 = suboptimal but helpful action, 0.0 = no action taken, negative penalty for harmful actions |
| **Investigation Efficiency** | 20% | `relevant_investigations / total_investigations` -- rewards targeted, efficient evidence gathering |
| **Time Factor** | 15% | `max(0.0, 1.0 - time_elapsed / (time_budget * 0.83))` -- decays to 0 when 83% of budget is consumed |
| **Collateral Avoidance** | 10% | Starts at 1.0, reduced by 0.15 for each harmful action (wrong restart, unnecessary escalation, etc.) |

The final score is clamped to **[0.0, 1.0]**.

### Novel Mechanics

**Time pressure with decay**: The time factor creates urgency without making slow-but-correct solutions worthless. An agent that solves in 3 steps gets a high time bonus; one that takes 12 steps still earns full marks on diagnosis and resolution, just with a reduced time component. Speed matters, but correctness matters more.

**Cascading failures**: If the agent takes too long, the simulated system degrades further. Dependent services begin failing, error rates increase, and new misleading symptoms appear. Each cascade event makes the environment harder to reason about and reduces the maximum achievable collateral avoidance score.

**Intermittent errors**: The hard task's logs show errors only ~30% of the time on any given check. The first investigation may return mostly clean output with only 2 error lines buried among 30+ successful requests. This tests whether the agent can detect sparse signals or dismisses a service as healthy after one clean-looking log check.

**Minimum investigation gates**: The environment enforces that agents gather a minimum amount of evidence before submitting a diagnosis. This prevents lucky guessing and ensures that high scores reflect genuine reasoning, not random exploration.

---

## Setup & Usage

### Prerequisites

- Python 3.11+
- Docker (for containerized deployment)
- An OpenAI-compatible API key (for running the baseline agent)

### Docker (Recommended)

```bash
docker build -t incident-env -f incident_env/server/Dockerfile .
docker run -p 7860:7860 incident-env
```

The server will be available at `http://localhost:7860`. Verify with:

```bash
curl http://localhost:7860/health
# {"status": "healthy"}
```

### Local Development

```bash
pip install -e .
uvicorn incident_env.server.app:app --host 0.0.0.0 --port 7860
```

### Running the Baseline Agent

```bash
export OPENAI_API_KEY=sk-...
python -m incident_env.baseline.run_baseline
```

The script connects to the running server, runs the agent through all three tasks, and prints per-task scores with a final average.

### Using the Python Client

```python
from incident_env.client import IncidentEnv
from incident_env.models import IncidentAction

env = IncidentEnv(url="http://localhost:7860")

# Reset for a specific task
obs = env.reset(task_id="easy_oom")

# Investigate
action = IncidentAction(
    action_type="investigate",
    target="user-service",
    command="logs"
)
result = env.step(action)
print(result.observation.message)
print(result.observation.investigation_result)

# Diagnose
action = IncidentAction(
    action_type="diagnose",
    target="user-service",
    command="OOM from v2.4.1 memory-intensive caching deployment"
)
result = env.step(action)

# Act
action = IncidentAction(
    action_type="act",
    target="user-service",
    command="rollback",
    parameters={"version": "2.4.0"}
)
result = env.step(action)
print(f"Reward: {result.reward}, Done: {result.done}")
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | `GET` | Root endpoint. Returns environment name and version. |
| `/health` | `GET` | Health check. Returns `200 OK` with `{"status": "healthy"}`. |
| `/tasks` | `GET` | List all tasks with IDs, difficulty levels, descriptions, and full action schema. |
| `/reset` | `POST` | Reset environment and start a new episode. Accepts `{"task_id": "easy_oom"}`. |
| `/step` | `POST` | Submit an action and receive an observation. Accepts an `IncidentAction` JSON body. |
| `/state` | `GET` | Retrieve current environment state (episode ID, step count, task ID). |
| `/schema` | `GET` | Full JSON schema for `IncidentAction` and `IncidentObservation` models. |
| `/grader` | `POST` | Compute grader score for a completed episode. Accepts `{"task_id": "...", "episode_id": "..."}`. |
| `/baseline` | `POST` | Trigger baseline inference. Returns per-task scores and average. |
| `/ws` | `WebSocket` | WebSocket endpoint for persistent, stateful agent sessions. |
| `/docs` | `GET` | Auto-generated Swagger/OpenAPI documentation (FastAPI built-in). |

### Example: GET /tasks

```json
{
  "tasks": [
    {
      "id": "easy_oom",
      "name": "Single Service OOM Crash",
      "difficulty": "easy",
      "max_steps": 15,
      "description": "user-service is returning 503 errors due to an OutOfMemoryError from a recent deployment"
    },
    {
      "id": "medium_db_pool",
      "name": "Cascading Database Connection Pool Exhaustion",
      "difficulty": "medium",
      "max_steps": 15,
      "description": "payment-service timeouts caused by database connection pool exhaustion from user-service leak"
    },
    {
      "id": "hard_canary",
      "name": "Intermittent Canary Deployment with OAuth Provider Failures",
      "difficulty": "hard",
      "max_steps": 15,
      "description": "Intermittent 5xx errors from auth-service canary deployment affecting provider-B OAuth tokens"
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
│   ├── easy.py                        # Single Service OOM scenario data
│   ├── medium.py                      # Cascading DB Pool Exhaustion scenario data
│   └── hard.py                        # Intermittent Canary + OAuth scenario data
├── graders/
│   ├── __init__.py
│   └── grader.py                      # Deterministic grading logic (5-component scoring)
├── baseline/
│   ├── __init__.py
│   └── run_baseline.py                # OpenAI API baseline agent loop
└── server/
    ├── __init__.py
    ├── incident_environment.py        # Core Environment subclass (reset/step/state)
    ├── app.py                         # FastAPI app + /tasks, /grader, /baseline endpoints
    ├── requirements.txt               # Server dependencies
    └── Dockerfile                     # Container image for HF Spaces deployment
```

---

## Design Principles

### Deterministic Scenarios
Given the same task ID and seed, the environment produces identical scenarios with identical logs, metrics, and system states. The same sequence of actions always produces the same rewards. This ensures reproducible evaluation and fair comparison between agents.

### Rich Text Observations
Log messages are modeled after real production output with realistic timestamps, log levels, Java/Python class names, and stack traces. Metric names follow industry conventions (`p99_latency_ms`, `error_rate_5xx`, `cpu_utilization_pct`). Service names are realistic (`api-gateway`, `auth-service`, `payment-service`). Agents must parse production-grade text, not simplified toy formats.

### Multi-Dimensional Grading
A binary correct/incorrect grader fails to distinguish systematic investigation from random guessing. The five-component grader captures investigation strategy, diagnostic accuracy, action quality, speed, and safety -- all dimensions that matter in real incident response and that create rich training signal for agent improvement.

### Simulated Time (Not Wall Clock)
Each action costs simulated time units. This makes evaluation deterministic and reproducible regardless of network latency or compute speed. The `time_elapsed / time_budget` ratio drives the time pressure reward component.

### Cascading System Model
In real production systems, failures propagate. A database connection pool exhaustion does not stay contained -- it ripples through every service that depends on it. IncidentEnv models this propagation, creating dynamic scenarios where the system gets worse over time. This rewards agents that act decisively and penalizes those that investigate endlessly without taking action.

### No External Dependencies at Runtime
The environment server has zero external API calls. All system simulation runs locally inside the container. Only the baseline inference script (a separate evaluation tool) calls external LLM APIs.

---

## Validation

```
$ openenv validate
[OK] incident: Ready for multi-mode deployment
```

The environment passes all OpenEnv validation checks:
- Server starts and responds to health checks
- `reset()` produces clean state with valid observations
- `step()` accepts valid actions and returns well-formed observations
- Graders produce deterministic scores in [0.0, 1.0]
- All custom endpoints (`/tasks`, `/grader`, `/baseline`) respond correctly
- Docker container builds and runs without errors

---

## License

MIT
