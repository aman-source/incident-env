"""
Easy scenario: Single Service OOM Crash.

The api-gateway is repeatedly crashing with OutOfMemoryError after a recent
deployment (v2.4.1) introduced unbounded request-body caching.  All other
services are healthy.  The agent must investigate the api-gateway, identify the
OOM as root cause, and either rollback or restart the service.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple
from uuid import uuid4

from incident_env.models import IncidentObservation, IncidentState
from incident_env.scenarios.base import BaseScenario, CascadingEffect, ServiceInfo


class EasyOOMScenario(BaseScenario):
    """Single Service OOM — easy difficulty.

    Root cause: api-gateway v2.4.1 introduced request-body caching that causes
    unbounded heap growth, triggering the Linux OOM killer every ~10 minutes.
    """

    def __init__(self) -> None:
        # -- Identity -----------------------------------------------------------
        self.task_id = "easy_oom"
        self.name = "Single Service OOM Crash"
        self.difficulty = "easy"
        self.description = (
            "The api-gateway service is repeatedly crashing due to an "
            "OutOfMemoryError introduced by a recent deployment.  Investigate, "
            "diagnose the root cause, and take corrective action."
        )

        # -- System topology ----------------------------------------------------
        self.services: Dict[str, ServiceInfo] = {
            "api-gateway": ServiceInfo(
                name="api-gateway",
                status="critical",
                latency_ms=30000,
                error_rate=0.95,
                cpu_pct=85.2,
                memory_pct=98.7,
                dependencies=["auth-service", "user-service"],
            ),
            "auth-service": ServiceInfo(
                name="auth-service",
                status="healthy",
                latency_ms=50,
                error_rate=0.002,
                cpu_pct=30.0,
                memory_pct=40.0,
                dependencies=["database"],
            ),
            "user-service": ServiceInfo(
                name="user-service",
                status="healthy",
                latency_ms=45,
                error_rate=0.001,
                cpu_pct=25.0,
                memory_pct=35.0,
                dependencies=["database"],
            ),
            "database": ServiceInfo(
                name="database",
                status="healthy",
                latency_ms=5,
                error_rate=0.0,
                cpu_pct=40.0,
                memory_pct=55.0,
            ),
            "cache": ServiceInfo(
                name="cache",
                status="healthy",
                latency_ms=2,
                error_rate=0.0,
                cpu_pct=15.0,
                memory_pct=30.0,
            ),
        }

        # -- Alert --------------------------------------------------------------
        self.initial_alert = (
            "[P1] FIRING: api-gateway High Error Rate\n"
            "Trigger: error_rate_5xx > 0.05 for 5m (current: 0.9471)\n"
            "Service: api-gateway | Cluster: prod-us-east-1 | Namespace: production\n"
            "Replicas: 3/3 affected | Pod restarts: 8 in last 30m\n"
            "Dashboard: https://grafana.internal/d/api-gw-overview\n"
            "Runbook: https://wiki.internal/runbooks/api-gateway-5xx\n"
            "On-call: @you (primary) | @senior-sre (secondary)\n"
            "Started: 2024-03-15T14:02:00Z | Duration: 30m 15s\n"
            "Related: [FIRING] api-gateway HighMemoryUsage, [FIRING] api-gateway PodCrashLooping"
        )

        # -- Investigation results ----------------------------------------------
        self.investigation_results: Dict[Tuple[str, str], str] = {}
        self._populate_investigation_results()

        # -- Ground truth -------------------------------------------------------
        self.root_cause = (
            "Memory leak in api-gateway v2.4.1 deployment - request body "
            "caching causes unbounded memory growth"
        )
        # Need 3+ for 1.0 — "memory" alone is too vague
        self.root_cause_keywords: Set[str] = {
            "oom",
            "memory leak",
            "api-gateway",
            "out of memory",
            "v2.4.1",
            "request body cache",
            "unbounded",
        }
        self.optimal_actions: List[str] = [
            "rollback api-gateway",
            "restart api-gateway",
        ]

        # -- Relevance set for efficiency reward --------------------------------
        self.relevant_investigations: Set[Tuple[str, str]] = {
            ("api-gateway", "logs"),
            ("api-gateway", "metrics"),
            ("api-gateway", "deployments"),
            ("api-gateway", "config"),
            ("api-gateway", "dependencies"),
            ("system", "overview"),
            ("system", "recent_changes"),
        }

        # -- Cascading effects --------------------------------------------------
        self.cascading_effects: List[CascadingEffect] = [
            CascadingEffect(
                time_threshold=120,
                service="user-service",
                effect="degraded",
                description=(
                    "[P2] FIRING: user-service Elevated Error Rate\n"
                    "Trigger: error_rate_5xx > 0.01 for 3m (current: 0.047)\n"
                    "Service: user-service | Cluster: prod-us-east-1\n"
                    "Correlation: api-gateway outage is blocking upstream request routing. "
                    "Clients retrying through alternate paths are overloading user-service directly.\n"
                    "Dashboard: https://grafana.internal/d/user-svc-overview\n"
                    "Related: [FIRING] api-gateway High Error Rate (30m, P1)"
                ),
            ),
            CascadingEffect(
                time_threshold=200,
                service="auth-service",
                effect="degraded",
                description=(
                    "[P2] FIRING: auth-service Health Check Failures\n"
                    "Trigger: liveness_probe_failures > 3 in 5m (current: 5)\n"
                    "Service: auth-service | Cluster: prod-us-east-1\n"
                    "Correlation: prolonged api-gateway outage is causing connection pool "
                    "saturation on auth-service — stale connections from api-gateway crash-restart "
                    "cycles are exhausting auth-service's inbound connection limit.\n"
                    "Dashboard: https://grafana.internal/d/auth-svc-overview\n"
                    "Related: [FIRING] api-gateway High Error Rate (45m, P1)"
                ),
            ),
        ]

        # -- Red herrings (none for easy) ---------------------------------------
        self.red_herrings: Dict[Tuple[str, str], str] = {}

        # -- Time / step budget -------------------------------------------------
        self.time_budget = 300
        self.max_steps = 15

        # -- Minimum investigation depth before diagnosis is accepted ----------
        self.min_investigations = 2

    # -------------------------------------------------------------------
    # Investigation result data
    # -------------------------------------------------------------------

    def _populate_investigation_results(self) -> None:  # noqa: C901 — intentionally long
        """Fill self.investigation_results with realistic production data."""

        # ===================================================================
        # api-gateway
        # ===================================================================
        self.investigation_results[("api-gateway", "logs")] = """\
=== kubectl logs -l app=api-gateway --all-containers --since=35m --tail=500 | head -80 ===
Namespace: production | Cluster: prod-us-east-1 | Context: prod-sre

2024-03-15T14:32:01.482Z ERROR [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.handler.RequestHandler - \
Unhandled panic in request handler requestId=req-8f2a1c3b traceId=trace-4d9e2f01a8c7 spanId=span-1a2b3c4d
  runtime: out of memory
  goroutine 18204 [running]:
    runtime.throw({0x1a2f4e0, 0x19})
        /usr/local/go/src/runtime/panic.go:1077 +0x48
    runtime.sysMap(0xc0b8000000, 0x4000000, 0x29e1c18)
        /usr/local/go/src/runtime/mem_linux.go:187 +0x10c
    runtime.(*mheap).grow(0x29a1000, 0x2000)
        /usr/local/go/src/runtime/mheap.go:1388 +0x1a8
    runtime.(*mheap).allocSpan(0x29a1000, 0x200, 0x0, 0x1)
        /usr/local/go/src/runtime/mheap.go:1170 +0x1e8
    runtime.(*mheap).alloc.func1()
        /usr/local/go/src/runtime/mheap.go:907 +0x5c
    runtime.systemstack()
        /usr/local/go/src/runtime/asm_amd64.s:496 +0x49
  Heap: 3,891M / 4,096M allocated | GC: 98.2% time spent | Last GC pause: 1,247ms | Next GC target: 4,096M (limit)
2024-03-15T14:32:01.490Z FATAL [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.process - \
Process killed by OOM killer (signal 9), exit status 137 | pid=1 | rss=4,089M | oom_score_adj=1000
2024-03-15T14:32:01.891Z INFO  [kube-system/kubelet] node=ip-10-0-47-132.ec2.internal - \
Liveness probe failed for container api-gateway in pod api-gateway-7f8b9c6d4-xk2mn: \
Get "http://10.0.47.214:8080/healthz": dial tcp 10.0.47.214:8080: connect: connection refused
2024-03-15T14:32:02.100Z INFO  [kube-system/kubelet] node=ip-10-0-47-132.ec2.internal - \
Container api-gateway in pod api-gateway-7f8b9c6d4-xk2mn restarting (restart count: 3, backoff: 40s)
2024-03-15T14:32:02.210Z WARN  [kube-system/kubelet] Back-off restarting failed container api-gateway \
in pod api-gateway-7f8b9c6d4-xk2mn_production(uid-a3f8c92d)
2024-03-15T14:31:45.102Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.middleware.MemoryWatchdog - \
Memory pressure CRITICAL: heap_alloc=3.81GiB sys=4.00GiB heap_objects=48,291,042 gc_cpu_fraction=0.982 \
mallocs_total=891,204,118 frees_total=842,913,076 stack_inuse=14MiB
2024-03-15T14:31:44.998Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.middleware.MemoryWatchdog - \
Live heap objects: 48,291,042 (startup baseline: 2,104,331) growth_factor=22.9x in 12m
2024-03-15T14:31:30.776Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
Cache unbounded growth: entries=3,412,887 total_bytes=3,221,504,000 avg_entry_bytes=943 \
eviction_policy=NONE ttl=NEVER
2024-03-15T14:31:15.443Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.pool.ConnectionPool - \
Request queue depth exceeding threshold: current=2,847 max_configured=1,000 \
oldest_pending_age=12.4s rejected_last_min=426
2024-03-15T14:30:12.201Z ERROR [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.handler.RequestHandler - \
Failed to allocate response buffer requestId=req-71c9e40a: cannot allocate 4096 bytes, heap exhausted \
(runtime.MemStats.HeapSys=4294967296, HeapIdle=0, HeapInuse=4294967296)
2024-03-15T14:29:55.112Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
Cache growth rate: +42MiB/min over last 5m (linear, not converging) — projected OOM in ~3m
2024-03-15T14:28:33.887Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.runtime.GCMonitor - \
GC pause duration=872ms (SLO target: <100ms) | runs_last_5min=347 | forced_gc=true | \
heap_goal=4.00GiB (at limit) | next_gc=immediate
2024-03-15T14:27:01.556Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
Caching request body for idempotent retry: method=POST path=/api/v2/users \
requestId=req-3f8a22d1 body_size=12,847B content_type=application/json
2024-03-15T14:26:58.901Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
Caching request body for idempotent retry: method=PUT path=/api/v2/orders/ord-991847 \
requestId=req-c4f1b739 body_size=8,712B content_type=application/json
2024-03-15T14:25:00.100Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.middleware.MemoryWatchdog - \
Memory pressure WARNING: heap_alloc=2.14GiB sys=4.00GiB heap_objects=31,042,118 gc_cpu_fraction=0.871
2024-03-15T14:21:12.443Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
Caching request body for idempotent retry: method=POST path=/api/v2/checkout \
requestId=req-a8f3c211 body_size=34,201B content_type=application/json
2024-03-15T14:20:00.001Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.main.Server - \
api-gateway v2.4.1 started | listening=:8080 | pid=1 | go_version=go1.21.6 | \
GOMAXPROCS=4 | initial_heap=412MiB | container_memory_limit=4096MiB
2024-03-15T14:20:00.002Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
RequestBodyCache initialized: eviction_policy=NONE max_entries=0(unlimited) ttl=0s(never) \
max_entry_size=10MiB storage=heap
--- previous instance logs (crashed at 14:19:58Z, pod api-gateway-7f8b9c6d4-xk2mn) ---
2024-03-15T14:19:58.712Z FATAL [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.process - \
Process killed by OOM killer (signal 9), exit status 137 | pid=1 | rss=4,091M | oom_score_adj=1000
2024-03-15T14:18:44.332Z WARN  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.middleware.MemoryWatchdog - \
Memory pressure CRITICAL: heap_alloc=3.92GiB sys=4.00GiB heap_objects=49,118,004 gc_cpu_fraction=0.991
2024-03-15T14:10:01.002Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.main.Server - \
api-gateway v2.4.1 started | listening=:8080 | pid=1 | container_memory_limit=4096MiB
--- previous instance logs (crashed at 14:09:59Z, pod api-gateway-7f8b9c6d4-xk2mn) ---
2024-03-15T14:09:59.881Z FATAL [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.process - \
Process killed by OOM killer (signal 9), exit status 137 | pid=1 | rss=4,087M | oom_score_adj=1000
2024-03-15T14:01:00.500Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.main.Server - \
api-gateway v2.4.1 started | listening=:8080 | pid=1 | go_version=go1.21.6 | \
GOMAXPROCS=4 | initial_heap=412MiB | container_memory_limit=4096MiB
2024-03-15T14:01:00.501Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.main.Server - \
Build info: version=v2.4.1 commit=abc123f built=2024-03-15T13:45:00Z \
builder=ci-pipeline/build-4821 base_image=golang:1.21.6-bookworm
2024-03-15T14:01:00.502Z INFO  [api-gateway-7f8b9c6d4-xk2mn] c.a.gateway.cache.RequestBodyCache - \
RequestBodyCache initialized: eviction_policy=NONE max_entries=0(unlimited) ttl=0s(never)

=== Similar OOM pattern observed on all 3 pods (xk2mn, a3m8k, p9q2r) ==="""

        self.investigation_results[("api-gateway", "metrics")] = """\
=== Prometheus Query Results ===
Source: https://prometheus.internal/graph | Range: last 30m | Step: 15s
Service: api-gateway (prod-us-east-1) | Deployment: api-gateway-v2.4.1

  Pods:                                                     Status
    api-gateway-7f8b9c6d4-xk2mn   uptime: 612s  restarts: 3   CrashLoopBackOff
    api-gateway-7f8b9c6d4-a3m8k   uptime: 480s  restarts: 3   CrashLoopBackOff
    api-gateway-7f8b9c6d4-p9q2r   uptime: 891s  restarts: 2   CrashLoopBackOff

  Latency (window=5m):
    http_request_duration_seconds{quantile="0.5"}:     12,480 ms
    http_request_duration_seconds{quantile="0.95"}:    25,891 ms
    http_request_duration_seconds{quantile="0.99"}:    31,204 ms
    http_request_duration_seconds{quantile="0.999"}:   48,102 ms

  Error Rates (window=5m):
    http_requests_total{code=~"5.."}                   rate: 426.2/s
      error_rate_5xx:                                  0.9471
    http_requests_total{code=~"4.."}                   rate: 8.2/s
      error_rate_4xx:                                  0.0182
    http_requests_total{code=~"5..|4.."}
      error_rate_total:                                0.9653

  Throughput:
    http_requests_total                                rate: 450.1/s   (baseline: 1,247/s | -63.9%)
    http_requests_total{code=~"2.."}                   rate: 24.1/s    (baseline: 1,241/s)
    dropped_requests_total:                            18,423          (since 14:02:00Z)

  Resources (container_*):
    container_cpu_usage_seconds_total                   84.7%
    container_memory_working_set_bytes                  3,891 MiB      <- CRITICAL
    container_spec_memory_limit_bytes                   4,096 MiB
    container_memory_usage_pct                          95.0%          <- CRITICAL
    go_gc_duration_seconds{quantile="0.5"}              0.847s
    go_gc_duration_seconds{quantile="0.99"}             2.103s
    go_gc_cpu_seconds_total / process_cpu_seconds_total 98.2%          <- CRITICAL (>95% time in GC)
    go_goroutines                                       18,204         (baseline: ~200)
    go_memstats_heap_objects                             48,291,042     (baseline: ~2,100,000)

  Connections:
    envoy_downstream_cx_active                          89             (baseline: 520)
    envoy_downstream_cx_destroy_remote_with_active_rq   2,841
    connection_pool_available                            411
    connection_pool_max                                  500

  Kubernetes Events (last 30m):
    3x  OOMKilled       pod/api-gateway-7f8b9c6d4-xk2mn    Container api-gateway OOMKilled
    3x  OOMKilled       pod/api-gateway-7f8b9c6d4-a3m8k    Container api-gateway OOMKilled
    2x  OOMKilled       pod/api-gateway-7f8b9c6d4-p9q2r    Container api-gateway OOMKilled
    9x  Unhealthy       pod/api-gateway-*                   Liveness probe failed
    14x Unhealthy       pod/api-gateway-*                   Readiness probe failed
    8x  BackOff         pod/api-gateway-*                   Back-off restarting failed container"""

        self.investigation_results[("api-gateway", "deployments")] = """\
=== kubectl rollout history deployment/api-gateway -n production ===
=== Argo CD Application: api-gateway | Sync Status: Synced | Health: Degraded ===

  ┌─ CURRENT ─────────────────────────────────────────────────────────────
  │ Version:    v2.4.1
  │ Deployed:   2024-03-15T14:01:00Z (31 min ago)
  │ Strategy:   RollingUpdate (maxSurge=1, maxUnavailable=0)
  │ Triggered:  ci-bot via PR #4821 (auto-merge, no human review)
  │ Pipeline:   https://ci.internal/pipelines/api-gateway/4821
  │ Commit:     abc123f "cache full request bodies for idempotent retries"
  │ Author:     jsmith@company.com
  │ Reviewers:  automated-merge-bot (no human reviewer)
  │ Approvals:  0/1 required (bypassed: auto-merge label applied)
  │ Image:      registry.internal/api-gateway:v2.4.1-sha-abc123f
  │ Replicas:   3/3 (all pods showing CrashLoopBackOff)
  │ Resources:  cpu=2000m/2000m  memory=4Gi/4Gi
  │ Status:     DEGRADED — 8 OOMKilled events across 3 pods in 30m
  │ Changelog:
  │   + Added RequestBodyCache for idempotent retry support
  │   + Cache stores full request bodies in-memory (no eviction policy)
  │   + Retry logic reads cached body on 5xx from upstream
  │   + Enabled for POST, PUT, PATCH methods
  │ Test Results:
  │   unit: 142/142 passed | integration: 38/38 passed
  │   load test: NOT RUN (skipped by auto-merge)
  │   memory profile: NOT RUN (skipped by auto-merge)
  └───────────────────────────────────────────────────────────────────────

  ┌─ PREVIOUS (rollback target) ──────────────────────────────────────────
  │ Version:    v2.4.0
  │ Deployed:   2024-03-12T10:00:00Z (3 days ago)
  │ Triggered:  k8s-deployer via PR #4798
  │ Commit:     def456a "rate limiter updates for /api/v2 endpoints"
  │ Author:     agarcia@company.com
  │ Reviewers:  bwilson@company.com (approved)
  │ Image:      registry.internal/api-gateway:v2.4.0-sha-def456a
  │ Status:     STABLE — ran 72h with 0 restarts, p99 < 200ms
  │ Rollback:   Available via `kubectl rollout undo deploy/api-gateway -n production`
  │             or `argocd app set api-gateway --parameter image.tag=v2.4.0`
  └───────────────────────────────────────────────────────────────────────

  ┌─ ARCHIVED ────────────────────────────────────────────────────────────
  │ v2.3.9  2024-03-08T15:30:00Z  "TLS certificate rotation"    STABLE (superseded)
  │ v2.3.8  2024-03-01T09:00:00Z  "Structured logging migration" STABLE (superseded)
  └───────────────────────────────────────────────────────────────────────"""

        self.investigation_results[("api-gateway", "dependencies")] = """\
=== Istio Service Mesh — Dependency Map for api-gateway ===
Source: Kiali dashboard | Namespace: production | Time range: last 30m

  api-gateway (v2.4.1) — CRITICAL
  ├─→ auth-service (v3.1.0)     [latency p99: 62ms | error_rate: 0.2% | circuit: CLOSED]
  │   └─→ database (PostgreSQL 15.4) [latency p99: 8ms | error_rate: 0.0% | pool: 18/50]
  ├─→ user-service (v4.2.3)     [latency p99: 58ms | error_rate: 0.1% | circuit: CLOSED]
  │   ├─→ database (PostgreSQL 15.4) [latency p99: 8ms | error_rate: 0.0% | pool: 12/50]
  │   └─→ cache (Redis 7.2.4)       [latency p99: 2.1ms | error_rate: 0.0% | hit_rate: 94.2%]
  ├─→ cache (Redis 7.2.4)       [latency p99: 2.1ms | error_rate: 0.0% | hit_rate: 94.7%]
  └─→ external: cdn (Cloudfront) [latency p99: 12ms | status: healthy]

  Upstream callers:
    load-balancer (Envoy 1.28.1)  →  api-gateway    [502/503 rate: 94.7%]
    cdn (Cloudfront)              →  api-gateway    [origin error rate: elevated]

  Istio Circuit Breaker Status:
    api-gateway → auth-service:   CLOSED (healthy)
    api-gateway → user-service:   CLOSED (healthy)
    api-gateway → cache:          CLOSED (healthy)
    load-balancer → api-gateway:  OPEN (tripped at 14:08:00Z, 50% traffic shed)

  Diagnosis: All downstream dependencies are healthy and responding within SLO.
  The issue is isolated to api-gateway itself — downstream services report reduced
  inbound traffic from api-gateway (requests are dying inside api-gateway before
  reaching downstream). No dependency-related root cause detected."""

        self.investigation_results[("api-gateway", "config")] = """\
=== ConfigMap: api-gateway-config (production namespace) ===
=== Image: registry.internal/api-gateway:v2.4.1-sha-abc123f ===

api-gateway/config.yaml — Active Configuration (v2.4.1)

  server:
    port: 8080
    max_connections: 500
    read_timeout_ms: 30000
    write_timeout_ms: 30000
    max_header_bytes: 1048576
    max_concurrent_requests: 5000
    graceful_shutdown_timeout_ms: 15000

  request_body_cache:                  # <- NEW in v2.4.1 (PR #4821)
    enabled: true                      # <- NEW
    max_entries: 0                     # <- UNLIMITED (no eviction!)
    max_entry_size_bytes: 10485760     # 10MB per entry
    ttl_seconds: 0                     # <- NEVER EXPIRES
    eviction_policy: none              # <- NO EVICTION
    storage_backend: heap              # in-process memory

  retry:
    enabled: true
    max_attempts: 3
    backoff_base_ms: 100
    backoff_max_ms: 5000
    backoff_multiplier: 2.0
    idempotent_methods: [POST, PUT, PATCH]   # <- was: [] (v2.4.0)
    cache_request_bodies: true               # <- NEW in v2.4.1

  rate_limiter:
    enabled: true
    requests_per_second: 1500
    burst: 200
    key: client_ip

  health_check:
    liveness_path: /healthz
    readiness_path: /readyz
    interval_seconds: 10
    failure_threshold: 3

  resources:                           # from deployment manifest
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi

  --- DIFF: v2.4.0 → v2.4.1 (PR #4821) ---
  + request_body_cache.enabled: true
  + request_body_cache.max_entries: 0           # UNBOUNDED — no limit on cached entries
  + request_body_cache.max_entry_size_bytes: 10485760
  + request_body_cache.ttl_seconds: 0           # INFINITE — entries never expire
  + request_body_cache.eviction_policy: none     # NO EVICTION — memory only grows
  + request_body_cache.storage_backend: heap
  ~ retry.idempotent_methods: [] → [POST, PUT, PATCH]
  + retry.cache_request_bodies: true

  ANALYSIS: The new request_body_cache config has no upper bound on entries and
  no TTL. At ~1,200 req/s with avg body ~1KB, this accumulates ~72MB/min of
  cached bodies. With a 4GiB memory limit, OOM is expected within ~50 minutes
  of sustained traffic. Actual OOM observed at ~10 min intervals due to larger
  request bodies (avg ~8KB observed in production)."""

        # ===================================================================
        # auth-service (HEALTHY — should not distract the agent)
        # ===================================================================
        self.investigation_results[("auth-service", "logs")] = """\
=== kubectl logs -l app=auth-service --all-containers --since=60m --tail=200 ===
Namespace: production | Cluster: prod-us-east-1

2024-03-15T14:31:42.118Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.handler.TokenHandler - \
Token validated requestId=req-d4a91c82 traceId=trace-8e1f3a72b4d9 userId=u-8827 \
token_type=Bearer issuer=auth-service scope=read:profile latency_ms=12
2024-03-15T14:31:40.442Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.handler.TokenHandler - \
Token validated requestId=req-f2c8819a traceId=trace-91b4e2d3c8f1 userId=u-3341 \
token_type=Bearer issuer=auth-service scope=read:profile,write:orders latency_ms=9
2024-03-15T14:31:38.201Z DEBUG [auth-service-5c9d8e7f2-vm4nl] c.a.auth.cache.TokenCache - \
Cache hit for token_hash=sha256:4f8a... userId=u-5519 remaining_ttl=2847s
2024-03-15T14:30:00.112Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.health.HealthCheck - \
Health check passed: db_pool=18/50 token_cache_size=8,412/10,000 jwt_key_age=1h42m \
goroutines=87 heap_alloc=312MiB
2024-03-15T14:29:30.001Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.rotation.KeyRotator - \
JWT signing key rotation completed: new_key_id=k-2024031514 algorithm=RS256 \
previous_key_id=k-2024031510 (retained for 24h validation window)
2024-03-15T14:25:00.500Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.health.HealthCheck - \
Health check passed: db_pool=16/50 token_cache_size=8,201/10,000 goroutines=84 heap_alloc=308MiB
2024-03-15T14:20:00.100Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.health.HealthCheck - \
Health check passed: db_pool=17/50 token_cache_size=7,998/10,000 goroutines=82 heap_alloc=305MiB
2024-03-15T14:15:00.201Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.health.HealthCheck - \
Health check passed: db_pool=15/50 token_cache_size=7,843/10,000 goroutines=81 heap_alloc=301MiB
2024-03-15T14:10:00.087Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.handler.TokenHandler - \
OIDC provider sync completed: provider=google.com jwks_keys=3 next_sync=300s
2024-03-15T14:05:00.334Z INFO  [auth-service-5c9d8e7f2-vm4nl] c.a.auth.health.HealthCheck - \
Health check passed: db_pool=14/50 goroutines=79 heap_alloc=298MiB

No ERROR or WARN level entries in the last 60 minutes.
Total requests served (last 60m): 20,412 | Success rate: 99.8%"""

        self.investigation_results[("auth-service", "metrics")] = """\
=== Prometheus Query Results ===
Source: https://prometheus.internal/graph | Range: last 30m | Step: 15s
Service: auth-service (prod-us-east-1) | Deployment: auth-service-v3.1.0

  Pod: auth-service-5c9d8e7f2-vm4nl   uptime: 259,412s (3d 0h 3m)   restarts: 0

  Latency (window=5m):
    http_request_duration_seconds{quantile="0.5"}:     18 ms
    http_request_duration_seconds{quantile="0.95"}:    48 ms
    http_request_duration_seconds{quantile="0.99"}:    62 ms

  Error Rates:
    error_rate_5xx:                    0.002     (within SLO < 0.01)
    error_rate_4xx:                    0.008     (normal — invalid tokens)

  Throughput:
    http_requests_total                rate: 340/s   (baseline: 380/s, within normal variance)
    http_requests_total{code=~"2.."}   rate: 337/s

  Resources:
    container_cpu_usage_seconds_total              30.1%
    container_memory_working_set_bytes             812 MiB   (limit: 2,048 MiB)
    container_memory_usage_pct                     39.6%
    go_goroutines                                  87
    go_gc_duration_seconds{quantile="0.99"}        0.012s

  Connections:
    envoy_downstream_cx_active                     312
    db_pool_active                                 18/50

  Status: HEALTHY — all metrics within normal operating range. No anomalies detected."""

        self.investigation_results[("auth-service", "deployments")] = """\
=== kubectl rollout history deployment/auth-service -n production ===

  ┌─ CURRENT ─────────────────────────────────────────────────────────────
  │ Version:    v3.1.0
  │ Deployed:   2024-03-10T08:00:00Z (5 days ago)
  │ Commit:     e7f891c "Add OIDC provider support (Google, Okta)"
  │ Author:     mpark@company.com
  │ Reviewers:  jdoe@company.com (approved)
  │ Status:     STABLE — 5 days uptime, 0 restarts, no anomalies
  │ Test Results: unit 89/89 | integration 24/24 | load test PASSED
  └───────────────────────────────────────────────────────────────────────

  ┌─ ARCHIVED ────────────────────────────────────────────────────────────
  │ v3.0.9  2024-03-03T11:30:00Z  "Fix token expiry edge case"    STABLE (superseded)
  │ v3.0.8  2024-02-25T09:00:00Z  "Add rate limiting to /token"   STABLE (superseded)
  └───────────────────────────────────────────────────────────────────────

  No deployments in the last 5 days. Last change was v3.1.0 on March 10."""

        self.investigation_results[("auth-service", "dependencies")] = """\
=== Istio Service Mesh — Dependency Map for auth-service ===

  auth-service (v3.1.0) — HEALTHY
  └─→ database (PostgreSQL 15.4)   [latency p99: 8ms | error_rate: 0.0% | pool: 18/50 active]

  Upstream callers:
    api-gateway → auth-service   [latency p99: 62ms | error_rate: 0.2% | circuit: CLOSED]

  No issues detected in dependency chain. All circuits healthy."""

        self.investigation_results[("auth-service", "config")] = """\
=== ConfigMap: auth-service-config (production namespace) ===

auth-service/config.yaml — Active Configuration (v3.1.0)

  jwt:
    signing_algorithm: RS256
    token_expiry_seconds: 3600
    refresh_expiry_seconds: 86400
    key_rotation_interval_hours: 4

  token_cache:
    max_size: 10000
    ttl_seconds: 3600
    eviction_policy: lru

  database:
    pool_size: 50
    max_idle_connections: 10
    connection_timeout_ms: 5000

  oidc_providers:              # Added in v3.1.0
    - name: google
      issuer: https://accounts.google.com
      jwks_sync_interval_seconds: 300

  No configuration changes since v3.1.0 deployment (5 days ago)."""

        # ===================================================================
        # user-service (HEALTHY)
        # ===================================================================
        self.investigation_results[("user-service", "logs")] = """\
=== kubectl logs -l app=user-service --all-containers --since=60m --tail=200 ===
Namespace: production | Cluster: prod-us-east-1

2024-03-15T14:31:12.334Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.handler.UserHandler - \
GET /api/v2/users/u-8827 completed requestId=req-7c1a4f89 traceId=trace-2b8e4d91c3a7 \
status=200 latency_ms=22 cache=MISS db_query_ms=18 response_bytes=1,247
2024-03-15T14:31:10.112Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.handler.UserHandler - \
GET /api/v2/users/u-3341 completed requestId=req-918b3c4d traceId=trace-4f2a8c71e9b3 \
status=200 latency_ms=18 cache=MISS db_query_ms=14 response_bytes=1,102
2024-03-15T14:30:55.778Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.handler.UserHandler - \
GET /api/v2/users/u-5519 completed requestId=req-c4f2918a traceId=trace-7d3b1e82f4a9 \
status=200 latency_ms=3 cache=HIT response_bytes=1,089
2024-03-15T14:30:41.221Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.handler.UserHandler - \
GET /api/v2/users/u-1147/profile completed requestId=req-a1b2c3d4 status=200 latency_ms=8 cache=HIT
2024-03-15T14:30:00.201Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.health.HealthCheck - \
Health check passed: db_pool=12/50 cache_hit_rate=94.2% goroutines=62 heap_alloc=284MiB
2024-03-15T14:25:00.100Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.health.HealthCheck - \
Health check passed: db_pool=11/50 cache_hit_rate=94.1% goroutines=60 heap_alloc=279MiB
2024-03-15T14:20:00.300Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.health.HealthCheck - \
Health check passed: db_pool=13/50 cache_hit_rate=93.9% goroutines=64 heap_alloc=281MiB
2024-03-15T14:15:00.088Z INFO  [user-service-6b4a7d9e1-hn3tp] c.a.users.handler.UserHandler - \
Pagination cursor refreshed for /api/v2/users: cursor_id=cur-8812 page_size=50 total_users=142,891
2024-03-15T14:10:00.442Z DEBUG [user-service-6b4a7d9e1-hn3tp] c.a.users.cache.ProfileCache - \
Cache eviction cycle: evicted=412 current_size=8,847/10,000 eviction_policy=lru oldest_entry_age=298s

No ERROR or WARN level entries in the last 60 minutes.
Total requests served (last 60m): 17,841 | Success rate: 99.9%"""

        self.investigation_results[("user-service", "metrics")] = """\
=== Prometheus Query Results ===
Source: https://prometheus.internal/graph | Range: last 30m | Step: 15s
Service: user-service (prod-us-east-1) | Deployment: user-service-v4.2.3

  Pod: user-service-6b4a7d9e1-hn3tp   uptime: 259,412s (3d 0h 3m)   restarts: 0

  Latency (window=5m):
    http_request_duration_seconds{quantile="0.5"}:     20 ms
    http_request_duration_seconds{quantile="0.95"}:    44 ms
    http_request_duration_seconds{quantile="0.99"}:    58 ms

  Error Rates:
    error_rate_5xx:                    0.001     (within SLO < 0.01)
    error_rate_4xx:                    0.012     (normal — 404s for deleted users)

  Throughput:
    http_requests_total                rate: 290/s   (baseline: 310/s, within normal variance)
    http_requests_total{code=~"2.."}   rate: 286/s

  Resources:
    container_cpu_usage_seconds_total              25.4%
    container_memory_working_set_bytes             714 MiB   (limit: 2,048 MiB)
    container_memory_usage_pct                     34.9%
    go_goroutines                                  62
    go_gc_duration_seconds{quantile="0.99"}        0.008s

  Cache:
    profile_cache_hit_rate                         0.942
    profile_cache_size                             8,847 / 10,000
    profile_cache_evictions_total                  rate: 6.8/s

  Connections:
    envoy_downstream_cx_active                     245
    db_pool_active                                 12/50
    redis_pool_active                              8/20

  Status: HEALTHY — all metrics within normal operating range. No anomalies detected."""

        self.investigation_results[("user-service", "deployments")] = """\
=== kubectl rollout history deployment/user-service -n production ===

  ┌─ CURRENT ─────────────────────────────────────────────────────────────
  │ Version:    v4.2.3
  │ Deployed:   2024-03-11T14:00:00Z (4 days ago)
  │ Commit:     b3c8f91 "Fix pagination offset bug for cursor-based queries"
  │ Author:     lchen@company.com
  │ Reviewers:  agarcia@company.com (approved)
  │ Status:     STABLE — 4 days uptime, 0 restarts, no anomalies
  │ Test Results: unit 118/118 | integration 31/31 | load test PASSED
  └───────────────────────────────────────────────────────────────────────

  ┌─ ARCHIVED ────────────────────────────────────────────────────────────
  │ v4.2.2  2024-03-06T09:00:00Z  "Add user search by email index"  STABLE (superseded)
  │ v4.2.1  2024-02-28T11:30:00Z  "Profile photo upload resize"     STABLE (superseded)
  └───────────────────────────────────────────────────────────────────────

  No deployments in the last 4 days. Last change was v4.2.3 on March 11."""

        self.investigation_results[("user-service", "dependencies")] = """\
=== Istio Service Mesh — Dependency Map for user-service ===

  user-service (v4.2.3) — HEALTHY
  ├─→ database (PostgreSQL 15.4)   [latency p99: 8ms | error_rate: 0.0% | pool: 12/50 active]
  └─→ cache (Redis 7.2.4)          [latency p99: 2.1ms | error_rate: 0.0% | hit_rate: 94.2%]

  Upstream callers:
    api-gateway → user-service   [latency p99: 58ms | error_rate: 0.1% | circuit: CLOSED]

  No issues detected in dependency chain. All circuits healthy."""

        self.investigation_results[("user-service", "config")] = """\
=== ConfigMap: user-service-config (production namespace) ===

user-service/config.yaml — Active Configuration (v4.2.3)

  server:
    port: 8081
    max_concurrent_requests: 3000

  database:
    pool_size: 50
    max_idle_connections: 10
    connection_timeout_ms: 5000
    statement_cache_size: 256

  cache:
    provider: redis
    pool_size: 20
    ttl_seconds: 300
    max_entries: 10000
    eviction_policy: lru

  pagination:
    default_limit: 50
    max_limit: 200
    cursor_type: keyset

  No configuration changes since v4.2.3 deployment (4 days ago)."""

        # ===================================================================
        # database (HEALTHY)
        # ===================================================================
        self.investigation_results[("database", "logs")] = """\
=== PostgreSQL 15.4 logs — pod: database-primary-0 (StatefulSet) ===
Namespace: production | Cluster: prod-us-east-1

2024-03-15T14:31:22.050Z LOG  [database-primary-0] postgres[pid=1842] LOG: \
checkpoint complete: wrote 142 buffers (0.9%); 0 WAL file(s) added, 0 removed, \
1 recycled; write=5.012s, sync=0.034s, total=5.102s; sync files=42, longest=0.012s, average=0.001s; \
distance=18421 kB, estimate=19204 kB
2024-03-15T14:30:58.112Z LOG  [database-primary-0] postgres[pid=2104] LOG: \
duration: 3.201 ms  statement: SELECT u.id, u.name, u.email, u.created_at FROM users u WHERE u.id = $1
2024-03-15T14:30:55.887Z LOG  [database-primary-0] postgres[pid=2098] LOG: \
duration: 1.847 ms  statement: SELECT token_hash, user_id, expires_at FROM auth_tokens \
WHERE user_id = $1 AND expires_at > NOW()
2024-03-15T14:30:42.334Z LOG  [database-primary-0] postgres[pid=2104] LOG: \
duration: 2.118 ms  statement: SELECT u.id, u.name, u.email FROM users u \
WHERE u.email = $1 LIMIT 1
2024-03-15T14:26:22.001Z LOG  [database-primary-0] postgres[pid=1842] LOG: \
checkpoint complete: wrote 98 buffers (0.6%); write=4.891s, sync=0.028s, total=4.948s
2024-03-15T14:21:22.030Z LOG  [database-primary-0] postgres[pid=1842] LOG: \
checkpoint complete: wrote 104 buffers (0.6%); write=4.912s, sync=0.031s, total=4.982s
2024-03-15T14:20:01.442Z LOG  [database-primary-0] postgres[pid=1801] LOG: \
automatic vacuum of table "appdb.public.sessions": index scans: 1, pages: 0 removed, \
4821 remain, 0 are newly dead; tuples: 412 removed, 38291 remain, 0 are dead but not yet removable; \
avg read rate: 8.412 MB/s, avg write rate: 2.104 MB/s; elapsed: 0.842s
2024-03-15T14:15:00.112Z LOG  [database-primary-0] postgres[pid=1801] LOG: \
automatic analyze of table "appdb.public.users": avg_width: 128, n_distinct: -1, \
correlation: 0.998, rows_sampled: 30000, rows_total: 142891

No ERROR or WARNING level entries in the last 60 minutes.
Active connections: 38/200 | Idle: 162 | Waiting: 0
Oldest active transaction age: 12ms | No long-running queries detected."""

        self.investigation_results[("database", "metrics")] = """\
=== Prometheus Query Results ===
Source: https://prometheus.internal/graph | Range: last 30m | Step: 15s
Service: database (PostgreSQL 15.4, prod-us-east-1) | StatefulSet: database-primary

  Pod: database-primary-0   uptime: 5,184,000s (60d)   restarts: 0

  Query Performance:
    pg_stat_statements_mean_exec_time{quantile="0.5"}:   2.1 ms
    pg_stat_statements_mean_exec_time{quantile="0.99"}:  8.4 ms
    pg_stat_activity_max_tx_duration_seconds:             0.012

  Connections:
    pg_stat_activity_count{state="active"}:               38
    pg_stat_activity_count{state="idle"}:                  162
    pg_settings_max_connections:                           200
    pg_stat_activity_count{wait_event_type="Lock"}:       0

  Throughput:
    pg_stat_database_xact_commit / second:                480
    pg_stat_database_xact_rollback / second:              0.2
    pg_stat_database_tup_fetched / second:                12,847

  Cache & I/O:
    pg_stat_database_blks_hit / (blks_hit + blks_read):   0.994   (cache hit ratio)
    pg_statio_user_tables_heap_blks_hit_rate:              0.997
    node_disk_io_time_seconds_total                        rate: 0.12
    node_disk_read_bytes_total                             rate: 2.4 MiB/s
    node_disk_written_bytes_total                          rate: 4.1 MiB/s

  WAL & Replication:
    pg_stat_wal_records / second:                          1,204
    pg_wal_bytes_written / second:                         2.4 MiB
    pg_replication_lag_seconds:                            0.0     (single-node)

  Table Maintenance:
    pg_stat_user_tables_n_dead_tup{table="users"}:        12,401
    pg_stat_user_tables_last_autovacuum{table="users"}:   2024-03-15T14:20:01Z (11m ago)
    pg_stat_user_tables_last_autoanalyze{table="users"}:  2024-03-15T14:15:00Z (16m ago)

  Resources:
    container_cpu_usage_seconds_total:                     40.2%
    container_memory_working_set_bytes:                    5,632 MiB  (limit: 10,240 MiB)
    container_memory_usage_pct:                            55.0%
    node_filesystem_avail_bytes{mountpoint="/data"}:       67.4 GiB   (65.3% free)

  Status: HEALTHY — all metrics within normal operating range. No anomalies detected."""

        self.investigation_results[("database", "deployments")] = """\
=== Database Version & Schema History ===

  Engine: PostgreSQL 15.4 (Debian 15.4-2.pgdg120+1)
  Provisioned: 2024-01-15 | StatefulSet: database-primary (1 replica)
  No version changes in last 60 days.

  Recent Schema Migrations (Flyway):
    V47__2024-03-09  "CREATE INDEX CONCURRENTLY idx_users_email ON users(email)"
                     Author: lchen@company.com | Duration: 4.2s | Status: SUCCESS
    V46__2024-03-01  "ALTER TABLE orders ADD COLUMN idempotency_key VARCHAR(64)"
                     Author: jsmith@company.com | Duration: 0.8s | Status: SUCCESS
    V45__2024-02-20  "CREATE TABLE audit_log (...)"
                     Author: mpark@company.com | Duration: 0.3s | Status: SUCCESS

  No schema changes in the last 6 days. No pending migrations."""

        self.investigation_results[("database", "dependencies")] = """\
=== Dependency Map for database (PostgreSQL 15.4) ===

  database (PostgreSQL 15.4) — HEALTHY
  └─→ storage (EBS gp3, 100GiB)   [IOPS: 120/3,000 | throughput: 24/125 MiB/s | latency: 0.4ms]

  Upstream callers:
    auth-service → database   [pool: 18/50 | avg query: 3.2ms | errors: 0.0%]
    user-service → database   [pool: 12/50 | avg query: 2.8ms | errors: 0.0%]

  No dependencies on other application services.
  Total active connections: 38/200 (19% utilization). No connection pressure."""

        self.investigation_results[("database", "config")] = """\
=== PostgreSQL Configuration (postgresql.conf) ===

  max_connections: 200
  shared_buffers: 4GB
  effective_cache_size: 12GB
  work_mem: 64MB
  maintenance_work_mem: 512MB
  wal_buffers: 64MB
  checkpoint_completion_target: 0.9
  random_page_cost: 1.1
  effective_io_concurrency: 200
  max_worker_processes: 8
  max_parallel_workers_per_gather: 4
  log_min_duration_statement: 1000     # log queries > 1s
  log_checkpoints: on
  log_connections: off
  log_disconnections: off
  autovacuum: on
  autovacuum_max_workers: 3

  No configuration changes in the last 30 days. All parameters at production defaults."""

        # ===================================================================
        # cache (HEALTHY)
        # ===================================================================
        self.investigation_results[("cache", "logs")] = """\
=== kubectl logs -l app=cache --all-containers --since=60m --tail=100 ===
Namespace: production | Cluster: prod-us-east-1 | StatefulSet: cache-primary

2024-03-15T14:31:01.001Z INFO  [cache-primary-0] redis[pid=1] 1:M 15 Mar 2024 14:31:01.001 * \
Background saving started by pid 842
2024-03-15T14:31:01.412Z INFO  [cache-primary-0] redis[pid=1] 842:C 15 Mar 2024 14:31:01.412 * \
RDB: 0 MB of memory used by copy-on-write
2024-03-15T14:31:01.413Z INFO  [cache-primary-0] redis[pid=1] 1:M 15 Mar 2024 14:31:01.413 * \
Background saving terminated with success
2024-03-15T14:30:01.001Z INFO  [cache-primary-0] redis[pid=1] # Server
  redis_version:7.2.4
  redis_mode:standalone
  os:Linux 5.15.0-1053-aws x86_64
  uptime_in_seconds:604800
  uptime_in_days:7
  connected_clients:48
  blocked_clients:0
  used_memory_human:1.24G
  used_memory_rss_human:1.38G
  used_memory_peak_human:1.31G
  used_memory_peak_perc:94.66%
  mem_fragmentation_ratio:1.11
  total_connections_received:2841
  total_commands_processed:89421042
  instantaneous_ops_per_sec:3201
  keyspace_hits:4829102
  keyspace_misses:298411
  hit_rate:94.18%
  evicted_keys:0
  expired_keys:142891
  db0:keys=48291,expires=47102,avg_ttl=284102

No WARNING or ERROR entries. Redis operating normally for 7 days."""

        self.investigation_results[("cache", "metrics")] = """\
=== Prometheus Query Results ===
Source: https://prometheus.internal/graph | Range: last 30m | Step: 15s
Service: cache (Redis 7.2.4, prod-us-east-1) | StatefulSet: cache-primary

  Pod: cache-primary-0   uptime: 604,800s (7d)   restarts: 0

  Latency:
    redis_command_duration_seconds{cmd="get",quantile="0.5"}:    0.8 ms
    redis_command_duration_seconds{cmd="get",quantile="0.99"}:   2.1 ms
    redis_command_duration_seconds{cmd="set",quantile="0.5"}:    0.9 ms
    redis_command_duration_seconds{cmd="set",quantile="0.99"}:   2.4 ms

  Throughput:
    redis_commands_processed_total                  rate: 3,201/s
    redis_keyspace_hits_total                       rate: 3,011/s
    redis_keyspace_misses_total                     rate: 190/s
    redis_keyspace_hit_rate                         0.9418

  Memory:
    redis_memory_used_bytes                         1,332 MiB   (limit: 4,096 MiB)
    redis_memory_used_rss_bytes                     1,413 MiB
    redis_memory_peak_bytes                         1,341 MiB
    redis_memory_fragmentation_ratio                1.11
    redis_evicted_keys_total                        0           (not hitting maxmemory)

  Connections:
    redis_connected_clients                         48
    redis_blocked_clients                           0
    redis_rejected_connections_total                 0

  Keyspace:
    redis_db_keys{db="db0"}                         48,291
    redis_db_expires{db="db0"}                      47,102
    redis_expired_keys_total                        rate: 23.8/s

  Resources:
    container_cpu_usage_seconds_total               15.1%
    container_memory_working_set_bytes              1,413 MiB   (limit: 4,096 MiB)
    container_memory_usage_pct                      34.5%

  Status: HEALTHY — all metrics within normal operating range. No anomalies detected."""

        self.investigation_results[("cache", "deployments")] = """\
=== StatefulSet: cache-primary — Deployment History ===

  ┌─ CURRENT ─────────────────────────────────────────────────────────────
  │ Version:    Redis 7.2.4
  │ Deployed:   2024-02-20T09:00:00Z (23 days ago)
  │ Change:     Minor version upgrade 7.2.3 → 7.2.4 (security patches)
  │ Author:     infra-team@company.com
  │ Status:     STABLE — 23 days uptime, 0 restarts, no anomalies
  └───────────────────────────────────────────────────────────────────────

  No version changes or configuration updates in the last 23 days."""

        self.investigation_results[("cache", "dependencies")] = """\
=== Dependency Map for cache (Redis 7.2.4) ===

  cache (Redis 7.2.4) — HEALTHY
  └─→ storage (local NVMe SSD)   [IOPS: 840/50,000 | latency: 0.1ms]

  Upstream callers:
    api-gateway  → cache   [pool: 12/20 | hit_rate: 94.7% | errors: 0.0%]
    user-service → cache   [pool: 8/20  | hit_rate: 94.2% | errors: 0.0%]

  No dependencies on other application services.
  Total active connections: 48 (well within limits). No connection pressure."""

        self.investigation_results[("cache", "config")] = """\
=== Redis Configuration (redis.conf) ===

  bind: 0.0.0.0
  port: 6379
  maxmemory: 4gb
  maxmemory-policy: allkeys-lru
  save: ""                         # RDB persistence disabled (cache-only mode)
  appendonly: no                   # AOF disabled (cache-only mode)
  maxclients: 1000
  timeout: 300
  tcp-keepalive: 60
  lfu-log-factor: 10
  lfu-decay-time: 1
  lazyfree-lazy-eviction: yes
  lazyfree-lazy-expire: yes

  No configuration changes in the last 23 days. All parameters at production defaults."""

        # ===================================================================
        # system-level investigations
        # ===================================================================
        self.investigation_results[("system", "overview")] = """\
=== Incident Dashboard — Production Environment ===
Cluster: prod-us-east-1 | Kubernetes: v1.28.4-eks-a1b2c3d | Region: us-east-1
Nodes: 12/12 healthy | Control Plane: healthy | Istio: v1.20.2 | Envoy: v1.28.1
Generated: 2024-03-15T14:32:15Z

  ┌─────────────────────────────────────────────────────────────────────┐
  │ SERVICE              STATUS      ERROR RATE   MEMORY    RESTARTS   │
  ├─────────────────────────────────────────────────────────────────────┤
  │ api-gateway          CRITICAL    94.71%       98.7%     8/30m      │
  │ auth-service         HEALTHY      0.20%       39.6%     0          │
  │ user-service         HEALTHY      0.10%       34.9%     0          │
  │ database             HEALTHY      0.00%       55.0%     0          │
  │ cache                HEALTHY      0.00%       34.5%     0          │
  └─────────────────────────────────────────────────────────────────────┘

  Active Alerts (Alertmanager):
    [FIRING] P1  api-gateway HighErrorRate       error_rate_5xx > 0.05  for 28m   severity=critical
    [FIRING] P1  api-gateway HighMemoryUsage     memory_pct > 90%       for 25m   severity=critical
    [FIRING] P1  api-gateway PodCrashLooping     restarts > 3/30m       for 22m   severity=critical
    [FIRING] P2  api-gateway HighLatency         p99_latency > 10s      for 27m   severity=warning
    [OK]         auth-service                    all clear
    [OK]         user-service                    all clear
    [OK]         database                        all clear
    [OK]         cache                           all clear

  Recent Incidents (PagerDuty):
    INC-2024031501  2024-03-15T14:02:00Z  api-gateway outage (THIS INCIDENT)   Status: OPEN
    INC-2024030801  2024-03-08T22:15:00Z  Scheduled maintenance (completed)    Status: RESOLVED
    No other incidents in the last 14 days.

  Cluster Resources:
    CPU:    42% aggregate  (api-gateway pods at 85%, all others normal)
    Memory: 61% aggregate  (api-gateway pods at 98.7%, driving up cluster average)
    Disk:   34% aggregate  (no pressure)
    Network: Ingress 2.4 Gbps | Egress 1.8 Gbps (normal)
    Node pressure: none
    PodDisruptionBudget violations: api-gateway (minAvailable=2, available=0 during restarts)"""

        self.investigation_results[("system", "recent_changes")] = """\
=== Change Management — All Services (last 7 days) ===
Source: Argo CD + GitOps audit log | Cluster: prod-us-east-1

  2024-03-15T14:01:00Z  DEPLOYMENT  api-gateway v2.4.0 → v2.4.1
    Author:     jsmith@company.com
    PR:         #4821 "feat: idempotent retry with cached request bodies"
    Merge:      auto-merged by CI bot (auto-merge label, no human approval)
    Pipeline:   https://ci.internal/pipelines/api-gateway/4821
    Image:      registry.internal/api-gateway:v2.4.1-sha-abc123f
    Rollback:   Available — v2.4.0 image present in registry
    *** THIS IS THE ONLY DEPLOYMENT IN THE LAST 24 HOURS ***
    *** OOM crashes began within 10 minutes of this deployment ***

  2024-03-12T10:00:00Z  DEPLOYMENT  api-gateway v2.3.9 → v2.4.0
    Author:     agarcia@company.com
    PR:         #4798 "chore: rate limiter configuration updates"
    Merge:      approved by bwilson@company.com
    Status:     STABLE (ran 72h without incidents before v2.4.1 replaced it)

  2024-03-11T14:00:00Z  DEPLOYMENT  user-service v4.2.2 → v4.2.3
    Author:     lchen@company.com
    PR:         #4784 "fix: pagination offset bug"
    Merge:      approved by agarcia@company.com
    Status:     STABLE

  2024-03-10T08:00:00Z  DEPLOYMENT  auth-service v3.0.9 → v3.1.0
    Author:     mpark@company.com
    PR:         #4771 "feat: OIDC provider support"
    Merge:      approved by jdoe@company.com
    Status:     STABLE

  Infrastructure Changes (last 30 days): NONE
    - No Kubernetes version changes
    - No node pool scaling events
    - No network policy changes
    - No IAM/RBAC changes
  Database Schema Changes (last 6 days): NONE
    - Last migration: 2024-03-09 (idx_users_email)
  Configuration Changes (outside deployments): NONE"""

        self.investigation_results[("system", "dependency_graph")] = """\
=== Service Dependency Graph — Production Namespace ===
Source: Istio Kiali | Cluster: prod-us-east-1 | Generated: 2024-03-15T14:32:15Z

  external traffic
       │
       ▼
  load-balancer (Envoy 1.28.1, 3 replicas)
       │
       ▼
  api-gateway (v2.4.1, 3 replicas) ─── CRITICAL: OOMKilled, CrashLoopBackOff
       │
       ├──→ auth-service (v3.1.0, 2 replicas) ── HEALTHY
       │         │
       │         └──→ database (PostgreSQL 15.4, 1 replica) ── HEALTHY
       │
       ├──→ user-service (v4.2.3, 2 replicas) ── HEALTHY
       │         │
       │         ├──→ database (PostgreSQL 15.4) ── (shared instance)
       │         │
       │         └──→ cache (Redis 7.2.4, 1 replica) ── HEALTHY
       │
       └──→ cache (Redis 7.2.4) ── (shared instance)

  External dependencies:
    cdn (Cloudfront) ←→ api-gateway   [HEALTHY]

  Notes:
  - api-gateway is the single ingress point for all external traffic
  - database is shared by auth-service and user-service (connection pooling per-service)
  - cache is shared by api-gateway and user-service (key namespace isolation)
  - All downstream services healthy — issue is isolated to api-gateway"""

    # -------------------------------------------------------------------
    # Scoring
    # -------------------------------------------------------------------

    def score_resolution(self, actions_taken: List[str]) -> float:
        """Score the agent's corrective actions.

        Returns a float in [0.0, 1.0]:
          1.0  — rollback of api-gateway (best fix: removes faulty code)
          0.7  — restart of api-gateway (temporary fix, OOM will recur)
          0.3  — scale_up of api-gateway (wrong approach, more memory ≠ fix)
          0.0  — anything else
        """
        actions_lower = [a.lower() for a in actions_taken]
        joined = " ".join(actions_lower)

        # Best: rollback api-gateway to previous version
        if "rollback" in joined and "api-gateway" in joined:
            return 1.0

        # Acceptable: restart api-gateway (buys time, doesn't fix root cause)
        if "restart" in joined and "api-gateway" in joined:
            return 0.7

        # Poor: scale_up (more memory just delays the inevitable)
        if "scale_up" in joined and "api-gateway" in joined:
            return 0.3

        return 0.0

    # -------------------------------------------------------------------
    # State / observation factories
    # -------------------------------------------------------------------

    def create_initial_state(self) -> IncidentState:
        """Create the starting IncidentState for the easy OOM scenario."""
        return IncidentState(
            episode_id=str(uuid4()),
            step_count=0,
            task_id=self.task_id,
            difficulty=self.difficulty,
            root_cause=self.root_cause,
            optimal_actions=self.optimal_actions,
            agent_diagnosis="",
            agent_actions_taken=[],
            services_status={
                name: svc.status for name, svc in self.services.items()
            },
            time_elapsed=0,
            time_budget=self.time_budget,
            investigation_depth=0,
            correct_investigations=0,
            total_investigations=0,
            collateral_damage=0.0,
            resolved=False,
            diagnosed=False,
            accumulated_reward=0.0,
            investigated_targets=[],
            max_steps=self.max_steps,
        )

    def create_initial_observation(self) -> IncidentObservation:
        """Create the first observation the agent sees — the incoming alert."""
        return IncidentObservation(
            done=False,
            reward=0.0,
            metadata={
                "task_id": self.task_id,
                "difficulty": self.difficulty,
                "scenario": self.name,
            },
            message=(
                "=== INCIDENT RESPONSE CONSOLE ===\n"
                "You are the primary on-call SRE. A P1 alert has fired and requires "
                "immediate investigation, diagnosis, and corrective action.\n\n"
                f"{self.initial_alert}\n\n"
                "Available services: api-gateway, auth-service, user-service, database, cache\n"
                "Available commands:\n"
                "  investigate <service> <check>  — check: logs | metrics | deployments | dependencies | config\n"
                "  diagnose <service>             — submit root cause analysis\n"
                "  act <service> <command>        — command: restart | rollback | scale_up | scale_down | flush_cache | failover\n"
                "  escalate <team> <priority>     — team: backend | infrastructure | database | security | management\n\n"
                "Time is critical. The system is degrading. Begin investigation."
            ),
            alert_summary=self.initial_alert,
            system_status=self.get_system_status_dict(),
            investigation_result="",
            available_actions=self.get_available_actions(),
            action_result="",
            time_elapsed=0,
            time_budget=self.time_budget,
            hint="Start by investigating the service mentioned in the alert.",
        )
