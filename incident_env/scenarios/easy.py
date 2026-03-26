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
            "CRITICAL: api-gateway returning 503, error rate 95%. "
            "Started 30 minutes ago. Multiple downstream users reporting "
            "service unavailable errors."
        )

        # -- Investigation results ----------------------------------------------
        self.investigation_results: Dict[Tuple[str, str], str] = {}
        self._populate_investigation_results()

        # -- Ground truth -------------------------------------------------------
        self.root_cause = (
            "Memory leak in api-gateway v2.4.1 deployment - request body "
            "caching causes unbounded memory growth"
        )
        self.root_cause_keywords: Set[str] = {
            "oom",
            "memory leak",
            "api-gateway",
            "out of memory",
            "memory",
            "v2.4.1",
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
                    "ALERT: user-service experiencing elevated error rates. "
                    "api-gateway failure is preventing proper request routing."
                ),
            ),
            CascadingEffect(
                time_threshold=200,
                service="auth-service",
                effect="degraded",
                description=(
                    "ALERT: auth-service health checks failing intermittently. "
                    "Cascading impact from prolonged api-gateway outage."
                ),
            ),
        ]

        # -- Red herrings (none for easy) ---------------------------------------
        self.red_herrings: Dict[Tuple[str, str], str] = {}

        # -- Time / step budget -------------------------------------------------
        self.time_budget = 300
        self.max_steps = 15

    # -------------------------------------------------------------------
    # Investigation result data
    # -------------------------------------------------------------------

    def _populate_investigation_results(self) -> None:  # noqa: C901 — intentionally long
        """Fill self.investigation_results with realistic production data."""

        # ===================================================================
        # api-gateway
        # ===================================================================
        self.investigation_results[("api-gateway", "logs")] = """\
[2024-03-15T14:32:01.482Z] ERROR api-gateway/main.go:342 HTTP handler panic: runtime: out of memory
[2024-03-15T14:32:01.483Z] ERROR api-gateway/main.go:345 goroutine 18204 [running]:
    runtime.throw({0x1a2f4e0, 0x19})
        /usr/local/go/src/runtime/panic.go:1077 +0x48
    runtime.sysMap(0xc0b8000000, 0x4000000, 0x29e1c18)
        /usr/local/go/src/runtime/mem_linux.go:187 +0x10c
    runtime.(*mheap).grow(0x29a1000, 0x2000)
        /usr/local/go/src/runtime/mheap.go:1388 +0x1a8
[2024-03-15T14:32:01.484Z] FATAL api-gateway process killed by OOM killer (signal 9), exit status 137
[2024-03-15T14:32:01.490Z] INFO  kubernetes/kubelet Liveness probe failed for pod api-gateway-7f8b9c6d4-xk2mn: connection refused
[2024-03-15T14:32:02.100Z] INFO  kubernetes/kubelet Container api-gateway restarting (restart count: 3 in last 30m)
[2024-03-15T14:31:45.102Z] WARN  api-gateway/middleware.go:128 Memory pressure detected: heap_alloc=3.8GB, sys=4.0GB, gc_pct=98%
[2024-03-15T14:31:44.998Z] WARN  api-gateway/middleware.go:131 Live heap objects: 48,291,042 (up from 2,104,331 at startup)
[2024-03-15T14:31:30.776Z] WARN  api-gateway/cache.go:67 RequestBodyCache size=3,412,887 entries, total_bytes=3,221,504,000
[2024-03-15T14:31:15.443Z] WARN  api-gateway/pool.go:89 Request queue depth exceeding threshold: current=2847, max=1000
[2024-03-15T14:30:12.201Z] ERROR api-gateway/handler.go:201 Failed to allocate response buffer: cannot allocate 4096 bytes, heap exhausted
[2024-03-15T14:29:55.112Z] WARN  api-gateway/cache.go:71 RequestBodyCache growth rate: +42MB/min (not converging)
[2024-03-15T14:28:33.887Z] INFO  api-gateway/middleware.go:45 GC pause duration=872ms (target <100ms), heap growing unbounded
[2024-03-15T14:27:01.556Z] INFO  api-gateway/cache.go:34 Caching request body for idempotent retry: path=/api/v2/users, size=12.4KB
[2024-03-15T14:26:58.901Z] INFO  api-gateway/cache.go:34 Caching request body for idempotent retry: path=/api/v2/orders, size=8.7KB
[2024-03-15T14:25:00.100Z] WARN  api-gateway/middleware.go:128 Memory pressure detected: heap_alloc=2.1GB, sys=4.0GB, gc_pct=87%
[2024-03-15T14:21:12.443Z] INFO  api-gateway/cache.go:34 Caching request body for idempotent retry: path=/api/v2/checkout, size=34.2KB
[2024-03-15T14:20:00.001Z] INFO  api-gateway/main.go:58 api-gateway v2.4.1 started, listening on :8080
[2024-03-15T14:20:00.002Z] INFO  api-gateway/cache.go:22 RequestBodyCache initialized: eviction_policy=NONE, max_entries=unlimited
--- previous instance (crashed at 14:19:58Z) ---
[2024-03-15T14:19:58.712Z] FATAL api-gateway process killed by OOM killer (signal 9), exit status 137
[2024-03-15T14:18:44.332Z] WARN  api-gateway/middleware.go:128 Memory pressure detected: heap_alloc=3.9GB, sys=4.0GB, gc_pct=99%
[2024-03-15T14:10:01.002Z] INFO  api-gateway/main.go:58 api-gateway v2.4.1 started, listening on :8080
--- previous instance (crashed at 14:09:59Z) ---
[2024-03-15T14:09:59.881Z] FATAL api-gateway process killed by OOM killer (signal 9), exit status 137
[2024-03-15T14:01:00.500Z] INFO  api-gateway/main.go:58 api-gateway v2.4.1 started, listening on :8080
[2024-03-15T14:01:00.501Z] INFO  api-gateway/main.go:62 Build info: version=v2.4.1, commit=abc123f, built=2024-03-15T13:45:00Z
[2024-03-15T14:01:00.502Z] INFO  api-gateway/cache.go:22 RequestBodyCache initialized: eviction_policy=NONE, max_entries=unlimited"""

        self.investigation_results[("api-gateway", "metrics")] = """\
Service: api-gateway
  Latency:
    p50_latency_ms:            12500
    p95_latency_ms:            25800
    p99_latency_ms:            30000
    p999_latency_ms:           45000
  Error Rates:
    error_rate_5xx:            0.95
    error_rate_4xx:            0.02
    error_rate_total:          0.97
  Throughput:
    request_rate_rps:          450       (baseline: 1200, -62.5%)
    successful_rps:            22        (baseline: 1194)
    dropped_requests_total:    18423     (last 30 min)
  Resource Utilisation:
    cpu_utilization_pct:       85.2
    memory_utilization_pct:    98.7      *** CRITICAL ***
    memory_limit_bytes:        4294967296  (4.00 GB)
    memory_usage_bytes:        4240000000  (3.95 GB)
    memory_rss_bytes:          4185000000  (3.90 GB)
    gc_pause_ms_p99:           1250
    gc_pause_ms_avg:           850
    gc_runs_last_5min:         347       (normally ~12)
  Availability:
    restarts_last_hour:        3
    uptime_seconds:            612       (last restart 10 min ago)
    liveness_probe_failures:   9
    readiness_probe_failures:  14
  Connections:
    active_connections:        89        (baseline: 500+)
    connection_pool_exhausted: 2841
    pending_requests:          2847
  Pod Status:
    pod_count:                 3/3       (all pods showing same symptoms)
    pod api-gateway-7f8b9c6d4-xk2mn:  memory 98.4%, restarts 3
    pod api-gateway-7f8b9c6d4-r9p2j:  memory 97.9%, restarts 3
    pod api-gateway-7f8b9c6d4-zt5dl:  memory 99.1%, restarts 2"""

        self.investigation_results[("api-gateway", "deployments")] = """\
Deployment History for api-gateway:
  v2.4.1 - deployed 2024-03-15T14:01:00Z (30 min ago) by deploy-bot
    Changes: "Add request body caching for retry logic"
    Commit: abc123f - "cache full request bodies in memory for idempotent retries"
    PR: #4821 - "feat: idempotent retry with cached request bodies"
    Author: jsmith@company.com
    Reviewer: automated-merge-bot (no human review)
    Image: registry.internal/api-gateway:v2.4.1-sha-abc123f
    Replicas: 3/3
    Resource Limits: cpu=2000m, memory=4Gi
    Status: RUNNING (unstable - 3 OOM restarts since deploy)
    Rollback Target: v2.4.0

  v2.4.0 - deployed 2024-03-12T10:00:00Z (3 days ago) by k8s-deployer
    Changes: "Rate limiter configuration updates"
    Commit: def456a - "tune rate limiter token bucket parameters"
    Author: agarcia@company.com
    Reviewer: bwilson@company.com
    Image: registry.internal/api-gateway:v2.4.0-sha-def456a
    Replicas: 3/3
    Resource Limits: cpu=2000m, memory=4Gi
    Status: STABLE (ran 72 hours, 0 restarts, p99 < 200ms)

  v2.3.9 - deployed 2024-03-08T15:30:00Z (7 days ago)
    Changes: "TLS certificate rotation"
    Status: ARCHIVED (superseded by v2.4.0, no issues)

  v2.3.8 - deployed 2024-03-01T09:00:00Z (14 days ago)
    Changes: "Structured logging migration"
    Status: ARCHIVED"""

        self.investigation_results[("api-gateway", "dependencies")] = """\
Dependency Graph for api-gateway:
  api-gateway
  ├── auth-service          [HEALTHY]  latency p99=62ms  error_rate=0.002
  │   └── database          [HEALTHY]  latency p99=8ms   error_rate=0.000
  ├── user-service          [HEALTHY]  latency p99=58ms  error_rate=0.001
  │   └── database          [HEALTHY]  latency p99=8ms   error_rate=0.000
  ├── cache (redis)         [HEALTHY]  latency p99=3ms   error_rate=0.000
  └── external: cdn         [HEALTHY]  latency p99=12ms

  NOTE: All downstream dependencies are healthy. The issue appears to be
  localised to api-gateway itself. Downstream services report normal
  request volumes from api-gateway (reduced due to api-gateway dropping
  requests before they reach downstream)."""

        self.investigation_results[("api-gateway", "config")] = """\
Runtime Configuration for api-gateway (v2.4.1):
  server:
    port: 8080
    read_timeout: 30s
    write_timeout: 30s
    max_header_bytes: 1048576
    max_concurrent_requests: 5000
  retry:
    enabled: true
    max_retries: 3
    backoff_base_ms: 100
    idempotent_retry_enabled: true          # NEW in v2.4.1
    cache_request_bodies: true              # NEW in v2.4.1
    request_body_cache_max_size: 0          # 0 = unlimited  *** PROBLEM ***
    request_body_cache_ttl: 0s              # 0 = never evict  *** PROBLEM ***
  rate_limiter:
    enabled: true
    requests_per_second: 1500
    burst: 200
  resources:
    memory_limit: 4Gi
    cpu_limit: 2000m
    memory_request: 2Gi
    cpu_request: 1000m
  health_check:
    liveness_path: /healthz
    readiness_path: /readyz
    interval: 10s
    threshold: 3

  NOTE: Two new configuration keys were added in v2.4.1 for the request body
  cache feature. Both are set to unlimited/never-evict, meaning cached bodies
  accumulate without bound in heap memory."""

        # ===================================================================
        # auth-service (HEALTHY — should not distract the agent)
        # ===================================================================
        self.investigation_results[("auth-service", "logs")] = """\
[2024-03-15T14:30:00.112Z] INFO  auth-service/main.go:48 Health check OK
[2024-03-15T14:29:45.201Z] INFO  auth-service/handler.go:112 Token validated for user_id=u-8827, latency=12ms
[2024-03-15T14:29:44.998Z] INFO  auth-service/handler.go:112 Token validated for user_id=u-3341, latency=9ms
[2024-03-15T14:29:30.001Z] INFO  auth-service/handler.go:87 JWT rotation completed, new key_id=k-2024031514
[2024-03-15T14:25:00.500Z] INFO  auth-service/main.go:48 Health check OK
[2024-03-15T14:20:00.100Z] INFO  auth-service/main.go:48 Health check OK
[2024-03-15T14:15:00.201Z] INFO  auth-service/main.go:48 Health check OK
--- No errors or warnings in the last 60 minutes ---"""

        self.investigation_results[("auth-service", "metrics")] = """\
Service: auth-service
  p50_latency_ms:          18
  p99_latency_ms:          62
  error_rate_5xx:          0.002
  request_rate_rps:        340    (baseline: 380, within normal variance)
  cpu_utilization_pct:     30.1
  memory_utilization_pct:  40.3
  memory_limit_bytes:      2147483648  (2 GB)
  memory_usage_bytes:      866000000   (0.81 GB)
  restarts_last_hour:      0
  uptime_seconds:          259412  (3 days)
  active_connections:      312
  Status: HEALTHY — all metrics within normal operating range"""

        self.investigation_results[("auth-service", "deployments")] = """\
Deployment History for auth-service:
  v3.1.0 - deployed 2024-03-10T08:00:00Z (5 days ago)
    Changes: "Add OIDC provider support"
    Status: STABLE (no restarts, no anomalies)
  v3.0.9 - deployed 2024-03-03T11:30:00Z
    Status: ARCHIVED"""

        self.investigation_results[("auth-service", "dependencies")] = """\
Dependency Graph for auth-service:
  auth-service
  └── database (postgres)  [HEALTHY]  connection_pool: 18/50 in use
  No issues detected in dependency chain."""

        self.investigation_results[("auth-service", "config")] = """\
Runtime Configuration for auth-service (v3.1.0):
  jwt_expiry: 3600s
  token_cache_size: 10000
  database_pool_size: 50
  No recent configuration changes."""

        # ===================================================================
        # user-service (HEALTHY)
        # ===================================================================
        self.investigation_results[("user-service", "logs")] = """\
[2024-03-15T14:31:12.334Z] INFO  user-service/handler.go:98 GET /api/v2/users/u-8827 completed in 22ms
[2024-03-15T14:31:10.112Z] INFO  user-service/handler.go:98 GET /api/v2/users/u-3341 completed in 18ms
[2024-03-15T14:30:55.778Z] INFO  user-service/handler.go:142 Profile cache hit for user_id=u-5519
[2024-03-15T14:30:00.201Z] INFO  user-service/main.go:52 Health check OK
[2024-03-15T14:25:00.100Z] INFO  user-service/main.go:52 Health check OK
[2024-03-15T14:20:00.300Z] INFO  user-service/main.go:52 Health check OK
--- No errors or warnings in the last 60 minutes ---"""

        self.investigation_results[("user-service", "metrics")] = """\
Service: user-service
  p50_latency_ms:          20
  p99_latency_ms:          58
  error_rate_5xx:          0.001
  request_rate_rps:        290    (baseline: 310, within normal variance)
  cpu_utilization_pct:     25.4
  memory_utilization_pct:  35.1
  memory_limit_bytes:      2147483648  (2 GB)
  memory_usage_bytes:      752000000   (0.70 GB)
  restarts_last_hour:      0
  uptime_seconds:          259412  (3 days)
  active_connections:      245
  Status: HEALTHY — all metrics within normal operating range"""

        self.investigation_results[("user-service", "deployments")] = """\
Deployment History for user-service:
  v4.2.3 - deployed 2024-03-11T14:00:00Z (4 days ago)
    Changes: "Fix pagination offset bug"
    Status: STABLE (no restarts, no anomalies)
  v4.2.2 - deployed 2024-03-06T09:00:00Z
    Status: ARCHIVED"""

        self.investigation_results[("user-service", "dependencies")] = """\
Dependency Graph for user-service:
  user-service
  ├── database (postgres)  [HEALTHY]  connection_pool: 12/50 in use
  └── cache (redis)        [HEALTHY]  hit_rate: 94.2%
  No issues detected in dependency chain."""

        self.investigation_results[("user-service", "config")] = """\
Runtime Configuration for user-service (v4.2.3):
  database_pool_size: 50
  cache_ttl: 300s
  pagination_default_limit: 50
  No recent configuration changes."""

        # ===================================================================
        # database (HEALTHY)
        # ===================================================================
        self.investigation_results[("database", "logs")] = """\
[2024-03-15T14:30:00.050Z] LOG  checkpoint complete: wrote 142 buffers (0.9%); 0 WAL file(s) added
[2024-03-15T14:29:58.112Z] LOG  duration: 3.201 ms  statement: SELECT id, name, email FROM users WHERE id = $1
[2024-03-15T14:29:55.887Z] LOG  duration: 1.847 ms  statement: SELECT token_hash FROM auth_tokens WHERE user_id = $1
[2024-03-15T14:25:00.001Z] LOG  checkpoint complete: wrote 98 buffers (0.6%)
[2024-03-15T14:20:00.030Z] LOG  checkpoint complete: wrote 104 buffers (0.6%)
--- No errors or warnings. Routine WAL checkpoints only. ---"""

        self.investigation_results[("database", "metrics")] = """\
Service: database (PostgreSQL 15.4)
  query_latency_p50_ms:    2.1
  query_latency_p99_ms:    8.4
  active_connections:      38/200
  idle_connections:        162
  transactions_per_sec:    480
  dead_tuples:             12401      (autovacuum running normally)
  cache_hit_ratio:         0.994
  disk_iops:               120
  wal_write_bytes_sec:     2.4MB
  replication_lag_ms:      0          (single-node, no replicas)
  cpu_utilization_pct:     40.2
  memory_utilization_pct:  55.0
  disk_utilization_pct:    34.7
  Status: HEALTHY — all metrics within normal operating range"""

        self.investigation_results[("database", "deployments")] = """\
Deployment History for database:
  PostgreSQL 15.4 - provisioned 2024-01-15
    No version changes in last 60 days.
    Last schema migration: 2024-03-09 (add index on users.email)"""

        self.investigation_results[("database", "dependencies")] = """\
Dependency Graph for database:
  database (PostgreSQL 15.4)
  └── storage (EBS gp3)   [HEALTHY]  IOPS: 120/3000, throughput: 24MB/125MB
  No dependencies on other application services."""

        self.investigation_results[("database", "config")] = """\
Runtime Configuration for database:
  max_connections: 200
  shared_buffers: 4GB
  work_mem: 64MB
  effective_cache_size: 12GB
  No recent configuration changes."""

        # ===================================================================
        # cache (HEALTHY)
        # ===================================================================
        self.investigation_results[("cache", "logs")] = """\
[2024-03-15T14:30:01.001Z] # Server
redis_version:7.2.4
uptime_in_seconds:604800
connected_clients:48
used_memory_human:1.24G
used_memory_peak_human:1.31G
evicted_keys:0
keyspace_hits:4829102
keyspace_misses:298411
hit_rate:94.18%
--- No warnings. Stable operation. ---"""

        self.investigation_results[("cache", "metrics")] = """\
Service: cache (Redis 7.2.4)
  get_latency_p50_ms:      0.8
  get_latency_p99_ms:      2.1
  set_latency_p50_ms:      0.9
  set_latency_p99_ms:      2.4
  connected_clients:       48
  used_memory_bytes:       1332000000  (1.24 GB)
  max_memory_bytes:        4294967296  (4 GB)
  evicted_keys_total:      0
  hit_rate:                0.9418
  ops_per_sec:             3200
  cpu_utilization_pct:     15.1
  memory_utilization_pct:  30.0
  Status: HEALTHY — all metrics within normal operating range"""

        self.investigation_results[("cache", "deployments")] = """\
Deployment History for cache:
  Redis 7.2.4 - deployed 2024-02-20
    No version changes in last 23 days."""

        self.investigation_results[("cache", "dependencies")] = """\
Dependency Graph for cache:
  cache (Redis 7.2.4)
  └── storage (local SSD)  [HEALTHY]
  No dependencies on other application services."""

        self.investigation_results[("cache", "config")] = """\
Runtime Configuration for cache:
  maxmemory: 4gb
  maxmemory-policy: allkeys-lru
  save: disabled (cache-only mode)
  No recent configuration changes."""

        # ===================================================================
        # system-level investigations
        # ===================================================================
        self.investigation_results[("system", "overview")] = """\
=== System Health Overview ===
  Cluster: prod-us-east-1  |  Kubernetes 1.28  |  Nodes: 12/12 healthy

  Service Summary:
    api-gateway      CRITICAL   error_rate=95%   memory=98.7%   3 restarts/30min
    auth-service     HEALTHY    error_rate=0.2%  memory=40.3%   0 restarts
    user-service     HEALTHY    error_rate=0.1%  memory=35.1%   0 restarts
    database         HEALTHY    error_rate=0.0%  memory=55.0%   0 restarts
    cache            HEALTHY    error_rate=0.0%  memory=30.0%   0 restarts

  Active Alerts:
    [FIRING] api-gateway HighErrorRate  - error_rate > 50% for 28 min
    [FIRING] api-gateway HighMemoryUsage - memory > 90% for 25 min
    [FIRING] api-gateway PodCrashLooping - 3 restarts in 30 min
    [FIRING] api-gateway HighLatency - p99 > 10000ms for 27 min
    [OK]     auth-service - all clear
    [OK]     user-service - all clear
    [OK]     database - all clear
    [OK]     cache - all clear

  Recent Incidents:
    2024-03-15T14:02:00Z  api-gateway alerts began firing (30 min ago)
    No other incidents in the last 7 days.

  Node Resources:
    Cluster CPU:    42%  (normal)
    Cluster Memory: 61%  (normal, api-gateway pods are the outlier)
    Disk Pressure:  none"""

        self.investigation_results[("system", "recent_changes")] = """\
=== Recent Changes Across All Services (last 7 days) ===

  2024-03-15T14:01:00Z  api-gateway v2.4.0 -> v2.4.1
    Author: jsmith@company.com
    Change: "Add request body caching for retry logic"
    Merge: auto-merged by CI bot (no human approval)
    Rollback available: yes (v2.4.0 image present in registry)
    *** This is the only deployment in the last 24 hours ***

  2024-03-12T10:00:00Z  api-gateway v2.3.9 -> v2.4.0
    Author: agarcia@company.com
    Change: "Rate limiter configuration updates"

  2024-03-11T14:00:00Z  user-service v4.2.2 -> v4.2.3
    Author: lchen@company.com
    Change: "Fix pagination offset bug"

  2024-03-10T08:00:00Z  auth-service v3.0.9 -> v3.1.0
    Author: mpark@company.com
    Change: "Add OIDC provider support"

  No infrastructure changes (Kubernetes version, node pool, network) in last 30 days.
  No database schema changes in last 6 days.
  No configuration changes outside of deployments."""

        self.investigation_results[("system", "dependency_graph")] = """\
=== System Dependency Graph ===

  api-gateway ──> auth-service ──> database
       │
       └──> user-service ──> database
       │                └──> cache
       └──> cache
       └──> external:cdn

  Notes:
  - api-gateway is the single ingress point for all external traffic
  - database is shared by auth-service and user-service
  - cache is shared by api-gateway and user-service"""

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
                "INCIDENT ALERT — You are the on-call SRE. A critical alert has "
                "fired. Investigate the issue, diagnose the root cause, and take "
                "corrective action before the situation worsens.\n\n"
                f"Alert: {self.initial_alert}\n\n"
                "You have access to 5 services: api-gateway, auth-service, "
                "user-service, database, cache. Use 'investigate' to gather data, "
                "'diagnose' to submit your root cause analysis, 'act' to take a "
                "corrective action, or 'escalate' to page a team."
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
