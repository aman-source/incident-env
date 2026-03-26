"""Hard scenario: Intermittent Canary Deployment with Correlated Failures.

auth-service is running a 90/10 canary deployment. The canary version
(v5.1.0-canary) has a subtle bug in the new OAuth claims parser that fails
ONLY for tokens issued by provider-B (~10% of users). Meanwhile,
recommendation-service has an unrelated CPU spike from a scheduled ML
retraining job, and a DNS config change on CDN two hours ago is a resolved
red herring.

The result is that ~8% of overall auth requests fail (10% canary traffic x
~80% provider-B failure rate on canary pod). This cascades through
order-service and api-gateway because they depend on auth-service.

The agent must:
1. Notice the intermittent 500s are not uniformly distributed.
2. Trace the errors to auth-service (not recommendation-service).
3. Discover the canary deployment and the per-pod error breakdown.
4. Correlate failures with provider-B tokens on the canary pod.
5. Roll back the canary (or kill it) to resolve the incident.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple
from uuid import uuid4

from incident_env.models import IncidentObservation, IncidentState
from incident_env.scenarios.base import BaseScenario, CascadingEffect, ServiceInfo


# ---------------------------------------------------------------------------
# Log / metric text blocks
# ---------------------------------------------------------------------------

_AUTH_LOGS = """\
[2024-03-15T14:32:18Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_20184 provider=provider-A latency_ms=11 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:18Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_44920 provider=provider-C latency_ms=9 (pod: auth-stable-a3m8k)
[2024-03-15T14:32:19Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_38127 provider=provider-A latency_ms=13 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:19Z] ERROR auth-service/handler.go:112 Token validation failed: incompatible token format user_id=usr_91823 provider=provider-B error="unsupported claim structure: nested_permissions" (pod: auth-canary-x9k2m)
[2024-03-15T14:32:20Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_55301 provider=provider-A latency_ms=15 (pod: auth-stable-a3m8k)
[2024-03-15T14:32:20Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_73219 provider=provider-A latency_ms=8 (pod: auth-canary-x9k2m)
[2024-03-15T14:32:21Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_12847 provider=provider-B latency_ms=11 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:21Z] ERROR auth-service/handler.go:112 Token validation failed: incompatible token format user_id=usr_67234 provider=provider-B error="unsupported claim structure: nested_permissions" (pod: auth-canary-x9k2m)
[2024-03-15T14:32:22Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_33918 provider=provider-A latency_ms=9 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:22Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_28471 provider=provider-A latency_ms=12 (pod: auth-stable-a3m8k)
[2024-03-15T14:32:23Z] ERROR auth-service/handler.go:112 Token validation failed: incompatible token format user_id=usr_82156 provider=provider-B error="unsupported claim structure: nested_permissions" (pod: auth-canary-x9k2m)
[2024-03-15T14:32:23Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_19472 provider=provider-A latency_ms=7 (pod: auth-stable-a3m8k)
[2024-03-15T14:32:24Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_73891 provider=provider-B latency_ms=10 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:24Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_44192 provider=provider-A latency_ms=8 (pod: auth-canary-x9k2m)
[2024-03-15T14:32:25Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_90184 provider=provider-C latency_ms=12 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:25Z] ERROR auth-service/handler.go:112 Token validation failed: incompatible token format user_id=usr_16392 provider=provider-B error="unsupported claim structure: nested_permissions" (pod: auth-canary-x9k2m)
[2024-03-15T14:32:26Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_48271 provider=provider-B latency_ms=9 (pod: auth-stable-a3m8k)
[2024-03-15T14:32:26Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_52093 provider=provider-A latency_ms=14 (pod: auth-stable-7b4f9)
[2024-03-15T14:32:27Z] ERROR auth-service/handler.go:112 Token validation failed: incompatible token format user_id=usr_39471 provider=provider-B error="unsupported claim structure: nested_permissions" (pod: auth-canary-x9k2m)
[2024-03-15T14:32:27Z] INFO  auth-service/handler.go:89  Token validation successful user_id=usr_61845 provider=provider-A latency_ms=10 (pod: auth-stable-7b4f9)
NOTE: provider-B tokens succeed on stable pods (auth-stable-*) but fail on canary pod (auth-canary-x9k2m). provider-A and provider-C tokens succeed on all pods including canary."""

_AUTH_METRICS = """\
Service: auth-service (canary deployment active — v5.1.0-canary)
  Overall Metrics (last 15 min):
    p50_latency_ms: 45
    p95_latency_ms: 320
    p99_latency_ms: 800  (elevated — p99 baseline is 120ms)
    error_rate_5xx: 0.082
    request_rate_rps: 2400
    success_rate: 91.8%
    cpu_utilization_pct: 50.1
    memory_utilization_pct: 45.3
    active_connections: 4812
    connection_pool_usage_pct: 62.0

  Per-Pod Breakdown:
    auth-stable-7b4f9 (receives ~45% of traffic via round-robin):
      error_rate_5xx: 0.001  (nominal)
      request_rate_rps: 1080
      p99_latency_ms: 88
      provider-A error rate: 0.0%
      provider-B error rate: 0.0%
      provider-C error rate: 0.0%
      cpu_utilization_pct: 38.2
      memory_utilization_pct: 42.0

    auth-stable-a3m8k (receives ~45% of traffic via round-robin):
      error_rate_5xx: 0.001  (nominal)
      request_rate_rps: 1080
      p99_latency_ms: 92
      provider-A error rate: 0.0%
      provider-B error rate: 0.0%
      provider-C error rate: 0.0%
      cpu_utilization_pct: 39.7
      memory_utilization_pct: 43.1

    auth-canary-x9k2m (receives ~10% of traffic — canary):
      error_rate_5xx: 0.82  (CRITICAL — 82% of requests to this pod are failing)
      request_rate_rps: 240
      p99_latency_ms: 1850  (retries + error handling overhead)
      provider-A error rate: 0.0%  (unaffected)
      provider-B error rate: 100.0%  (ALL provider-B tokens fail on canary)
      provider-C error rate: 0.0%  (unaffected)
      cpu_utilization_pct: 78.4  (elevated from error-handling churn)
      memory_utilization_pct: 52.1

  Error Breakdown by OAuth Provider (across all pods):
    provider-A: 0.0% error rate (3,840 req/5min — unaffected)
    provider-B: ~82% error rate on canary, 0% on stable (420 req/5min — only fails on canary pod)
    provider-C: 0.0% error rate (540 req/5min — unaffected)

  Error Distribution by Time:
    14:10-14:15: 0.0% (canary not yet receiving provider-B traffic by chance)
    14:15-14:20: 6.2%  (first provider-B requests hit canary)
    14:20-14:25: 8.5%
    14:25-14:30: 7.8%
    14:30-14:35: 8.2%  (stabilized — consistent with 10% canary x provider-B ratio)

  Alert Correlations:
    - Error onset coincides with auth-service v5.1.0-canary deploy at 14:10Z
    - Errors are NOT correlated with database latency or cache miss rate
    - Errors ARE correlated with provider-B OAuth token presence in request"""

_AUTH_DEPLOYMENTS = """\
Deployment History for auth-service:

  v5.1.0-canary — deployed 2024-03-15T14:10:00Z (25 min ago) by ci-bot
    Commit: 7a8b9c0 — "migrate to structured claims validation library v3"
    PR: #2341 — "Upgrade claims parsing for provider compliance"
    Change Summary:
      - Replaced legacy token parser (pkg/auth/legacy_parser.go) with new
        structured claims library (github.com/org/claims-validator v3.0.1)
      - New library uses stricter schema validation for JWT claim structures
      - Intended to improve compliance with OAuth 2.1 spec
    Reviewers: @sarah-auth, @mike-platform (approved)
    CI Status: All unit tests passed, integration tests passed
    Image: registry.internal/auth-service:v5.1.0-canary
    Traffic Split: 10% canary (auth-canary-x9k2m) / 90% stable (auth-stable-*)
    Canary Policy: auto-promote after 2h if error_rate < 1%
    Rollback: instant via `kubectl set traffic auth-service --canary=0`
    Status: CANARY_ACTIVE — promotion blocked (error threshold exceeded)
    Known Issues: None documented in PR

  v5.0.4 (stable) — deployed 2024-03-10T08:00:00Z (5 days ago) by ci-bot
    Commit: 3d4e5f6 — "add structured logging for OAuth provider metrics"
    Changes: Minor logging improvements, no behavioral changes
    Status: STABLE
    Pods: auth-stable-7b4f9, auth-stable-a3m8k

  v5.0.3 — deployed 2024-03-03T14:30:00Z (12 days ago)
    Changes: Rate limiter tuning for provider-B (increased quota from 500 to 800 rps)
    Status: SUPERSEDED

  v5.0.2 — deployed 2024-02-28T10:00:00Z (16 days ago)
    Changes: Fixed connection pool leak on provider-C timeout path
    Status: SUPERSEDED"""

_AUTH_DEPENDENCIES = """\
Service: auth-service
  Upstream (services that call auth-service):
    - api-gateway (all authenticated requests pass through auth-service)
    - order-service (validates user tokens before processing orders)
    - payment-service (validates tokens for payment authorization)

  Downstream (services that auth-service depends on):
    - database: stores session data, token revocation lists, provider configs
      Connection status: HEALTHY, pool: 48/100 active
    - cache: caches validated tokens (TTL=300s) and provider JWKS keys
      Connection status: HEALTHY, hit_rate: 94.2%
      Note: cache miss does NOT explain errors — cache misses fall through to
      database lookup, which is also healthy

  OAuth Providers (external):
    - provider-A: HEALTHY (last checked 2min ago)
    - provider-B: HEALTHY (last checked 2min ago)
      Note: provider-B had a brief outage 5 days ago (2024-03-10, lasted 45min,
      fully resolved). JWKS keys rotated normally since then.
    - provider-C: HEALTHY (last checked 2min ago)"""

_AUTH_CONFIG = """\
Service: auth-service — Runtime Configuration

  Canary Configuration:
    canary_enabled: true
    canary_version: v5.1.0-canary
    canary_traffic_pct: 10
    canary_pod_selector: "app=auth-service,track=canary"
    canary_auto_promote: true
    canary_promote_after: 7200  # 2 hours
    canary_error_threshold: 0.01  # auto-promote blocked if error_rate > 1%
    canary_rollback_on_breach: false  # manual rollback required

  Token Validation Config:
    token_cache_ttl_sec: 300
    max_token_age_sec: 3600
    supported_providers: [provider-A, provider-B, provider-C]
    claims_validation_mode: "strict"  # <-- changed in v5.1.0 from "permissive"
    nested_claims_support: true  # <-- NEW in v5.1.0
    legacy_parser_fallback: false  # <-- DISABLED in v5.1.0 (was true in v5.0.4)

  Rate Limiting:
    per_provider_rps_limit: 800
    global_rps_limit: 3000
    burst_allowance: 1.5x

  Circuit Breaker:
    enabled: true
    error_threshold_pct: 50
    window_sec: 60
    half_open_after_sec: 30
    state: CLOSED  # has not tripped because overall error rate (8%) < threshold (50%)

  Notes:
    - v5.1.0-canary disabled legacy_parser_fallback. The old parser handled
      provider-B's non-standard nested_permissions claim gracefully. The new
      claims-validator v3 library rejects it as non-conforming.
    - provider-B uses a non-standard JWT claim structure (nested_permissions
      inside the `realm_access` claim) that deviates from RFC 7519.
    - This was documented in internal wiki but not flagged during PR review."""

_ORDER_LOGS = """\
[2024-03-15T14:33:01Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_91823 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:01Z] INFO  order-service/auth_client.go:72  Auth validation succeeded on retry for user_id=usr_91823 (retried to different auth pod)
[2024-03-15T14:33:02Z] INFO  order-service/handler.go:134 Order created order_id=ord_88291 user_id=usr_44192 total=42.99
[2024-03-15T14:33:03Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_67234 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:03Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_67234 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:04Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_67234 status=500 upstream=auth-service retry=3/3
[2024-03-15T14:33:04Z] ERROR order-service/handler.go:141 Order creation failed — authentication error user_id=usr_67234 error="upstream auth-service returned 500 after 3 retries"
[2024-03-15T14:33:05Z] INFO  order-service/handler.go:134 Order created order_id=ord_88292 user_id=usr_55301 total=18.50
[2024-03-15T14:33:06Z] INFO  order-service/handler.go:134 Order created order_id=ord_88293 user_id=usr_33918 total=127.00
[2024-03-15T14:33:07Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_82156 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:07Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_82156 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:07Z] WARN  order-service/auth_client.go:78  Auth validation succeeded on retry 3 for user_id=usr_82156 (hit stable pod after canary failure)
[2024-03-15T14:33:08Z] INFO  order-service/handler.go:134 Order created order_id=ord_88294 user_id=usr_82156 total=65.20
[2024-03-15T14:33:09Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_16392 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:09Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_16392 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:10Z] ERROR order-service/auth_client.go:67  Auth validation request failed for user_id=usr_16392 status=500 upstream=auth-service retry=3/3
[2024-03-15T14:33:10Z] ERROR order-service/handler.go:141 Order creation failed — authentication error user_id=usr_16392 error="upstream auth-service returned 500 after 3 retries"
NOTE: Intermittent auth failures. Some requests retry successfully (hit stable pod on retry), others exhaust retries (keep hitting canary). Error users correlate with auth-service canary failures."""

_ORDER_METRICS = """\
Service: order-service
  p50_latency_ms: 180
  p99_latency_ms: 900  (elevated — auth retries adding latency)
  error_rate_5xx: 0.072
  request_rate_rps: 850
  cpu_utilization_pct: 32.4
  memory_utilization_pct: 38.1

  Error Breakdown:
    auth_validation_failures: 68% of all 5xx errors
    database_errors: 0%
    internal_errors: 2%
    timeout_errors: 30% (auth retry timeouts)

  Dependency Health (as seen by order-service):
    auth-service: DEGRADED (intermittent 500s, retry success rate ~60%)
    database: HEALTHY
    payment-service: HEALTHY"""

_API_GATEWAY_LOGS = """\
[2024-03-15T14:34:01Z] WARN  api-gateway/proxy.go:201 Upstream error: auth-service returned 500 for request_id=req_a8f21 path=/api/v2/orders user_agent="Mozilla/5.0"
[2024-03-15T14:34:01Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_b2c43 path=/api/v2/users/profile status=200 latency_ms=62
[2024-03-15T14:34:02Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_d4e65 path=/api/v2/search status=200 latency_ms=85
[2024-03-15T14:34:02Z] WARN  api-gateway/proxy.go:201 Upstream error: auth-service returned 500 for request_id=req_f6g87 path=/api/v2/payments user_agent="PaymentSDK/2.1"
[2024-03-15T14:34:03Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_h8i09 path=/api/v2/orders status=200 latency_ms=340 (slow — auth retry)
[2024-03-15T14:34:03Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_j0k12 path=/api/v2/users/settings status=200 latency_ms=55
[2024-03-15T14:34:04Z] ERROR api-gateway/proxy.go:215 Request failed request_id=req_l2m34 path=/api/v2/orders status=502 error="all auth-service retries exhausted"
[2024-03-15T14:34:04Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_n4o56 path=/api/v2/recommendations status=200 latency_ms=210
[2024-03-15T14:34:05Z] INFO  api-gateway/proxy.go:189 Request completed request_id=req_p6q78 path=/api/v2/search status=200 latency_ms=79
NOTE: Intermittent 502s. All failures trace back to auth-service 500s. Non-auth paths (search, recommendations) are unaffected."""

_API_GATEWAY_METRICS = """\
Service: api-gateway
  p50_latency_ms: 120
  p95_latency_ms: 680
  p99_latency_ms: 1200  (elevated due to auth retry cascades)
  error_rate_5xx: 0.081
  request_rate_rps: 12000
  cpu_utilization_pct: 45.2
  memory_utilization_pct: 40.8

  Error Breakdown by Upstream:
    auth-service: accounts for 95% of all 5xx responses
    user-service: 0%
    payment-service: 2% (downstream of auth failures)
    order-service: 3% (downstream of auth failures)
    search-service: 0%

  Path-Level Error Rates:
    /api/v2/orders: 8.1% error rate (requires auth)
    /api/v2/payments: 7.9% error rate (requires auth)
    /api/v2/users/*: 8.0% error rate (requires auth)
    /api/v2/search: 0.1% error rate (no auth required)
    /api/v2/recommendations: 0.2% error rate (cached, auth optional)"""

_API_GATEWAY_DEPLOYMENTS = """\
Deployment History for api-gateway:
  v3.8.2 (current) — deployed 2024-03-08T12:00:00Z (7 days ago)
    Changes: "Upgrade HTTP/2 multiplexing, minor header parsing fix"
    Status: STABLE — no recent changes"""

_RECOMMENDATION_LOGS = """\
[2024-03-15T14:28:00Z] INFO  recommendation-service/ml_pipeline.go:234 Starting daily model retraining batch (scheduled cron: 0 14 * * *)
[2024-03-15T14:28:01Z] INFO  recommendation-service/ml_pipeline.go:240 Loading training data from data-lake: 2.3M user interactions (last 7 days)
[2024-03-15T14:28:02Z] INFO  recommendation-service/ml_pipeline.go:256 Feature extraction phase started, estimated duration: 25 min
[2024-03-15T14:28:15Z] INFO  recommendation-service/ml_pipeline.go:278 Feature extraction progress: 12% (280K/2.3M records)
[2024-03-15T14:29:00Z] WARN  recommendation-service/resource_monitor.go:45 CPU utilization at 85%, approaching autoscale threshold (90%)
[2024-03-15T14:30:00Z] WARN  recommendation-service/resource_monitor.go:45 CPU utilization at 92%, autoscale threshold breached
[2024-03-15T14:30:01Z] INFO  recommendation-service/autoscaler.go:78 HPA triggered: scaling from 3 to 5 replicas (target CPU: 70%)
[2024-03-15T14:30:02Z] INFO  recommendation-service/autoscaler.go:92 New pods recommendation-svc-d7e8f, recommendation-svc-g9h0i starting
[2024-03-15T14:31:00Z] INFO  recommendation-service/autoscaler.go:105 Pods ready. Traffic rebalancing in progress.
[2024-03-15T14:32:00Z] INFO  recommendation-service/health.go:45 Health check passed. Serving recommendations normally. p99 latency=195ms.
[2024-03-15T14:33:00Z] INFO  recommendation-service/ml_pipeline.go:278 Feature extraction progress: 48% (1.1M/2.3M records)
[2024-03-15T14:34:00Z] INFO  recommendation-service/resource_monitor.go:45 CPU utilization at 71% (post-scale). Within target range.
NOTE: This is a daily scheduled ML batch job. Autoscaler responded. No user-facing impact. Error rate remains at baseline (0.01%)."""

_RECOMMENDATION_METRICS = """\
Service: recommendation-service
  p50_latency_ms: 95
  p99_latency_ms: 200
  error_rate_5xx: 0.010  (baseline — no elevation)
  request_rate_rps: 3200
  cpu_utilization_pct: 92.3  (ALERT: high — but autoscaler active, trending down)
  memory_utilization_pct: 55.1
  replicas: 5 (scaled from 3 at 14:30Z)

  Autoscaler Status:
    trigger: CPU > 90% for 60s
    current_state: SCALING_COMPLETE
    target_cpu: 70%
    projected_cpu_after_scale: 55%

  Note: CPU spike is from daily ML model retraining (cron job). This happens
  every day at 14:00 UTC. Autoscaler handles it automatically. No correlation
  with the auth-service errors. Error rate is nominal."""

_RECOMMENDATION_DEPLOYMENTS = """\
Deployment History for recommendation-service:
  v2.14.0 (current) — deployed 2024-03-05T09:00:00Z (10 days ago)
    Changes: "Updated feature store connector, improved caching for cold-start users"
    Status: STABLE — no recent changes
  v2.13.8 — deployed 2024-02-25T16:00:00Z
    Changes: "Bug fix: handle missing user preference data gracefully"
    Status: SUPERSEDED"""

_DATABASE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  postgresql/log: checkpoint starting: time
[2024-03-15T14:32:01Z] INFO  postgresql/log: checkpoint complete: wrote 847 buffers (0.6%)
[2024-03-15T14:33:00Z] INFO  postgresql/log: automatic vacuum of table "auth_sessions": 1204 rows removed
[2024-03-15T14:34:00Z] INFO  postgresql/log: slow query: duration=45ms statement=SELECT * FROM token_revocations WHERE provider=$1 AND expires_at > NOW()
NOTE: Database is healthy. No lock contention, no connection exhaustion. The 45ms query is within normal range for revocation list lookup."""

_DATABASE_METRICS = """\
Service: database (PostgreSQL 15.4)
  p50_latency_ms: 4
  p99_latency_ms: 8
  error_rate: 0.001
  connections_active: 142
  connections_max: 500
  cpu_utilization_pct: 45.0
  memory_utilization_pct: 50.2
  disk_io_pct: 22.0
  replication_lag_ms: 0
  lock_waits: 0
  deadlocks_last_hour: 0
NOTE: All database metrics are nominal. No correlation with auth-service errors."""

_CACHE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  redis/server.go:312 Memory usage: 1.2GB / 4GB (28%)
[2024-03-15T14:33:00Z] INFO  redis/server.go:318 Key evictions last minute: 0
[2024-03-15T14:34:00Z] INFO  redis/server.go:324 Hit rate: 94.2% (8412 hits / 8929 total)
NOTE: Cache is healthy. Hit rate is normal. No eviction pressure."""

_CACHE_METRICS = """\
Service: cache (Redis 7.2)
  latency_ms: 3
  error_rate: 0.000
  hit_rate_pct: 94.2
  memory_utilization_pct: 28.0
  connections_active: 89
  evictions_per_min: 0
  cpu_utilization_pct: 12.4
NOTE: Cache is fully healthy. Token cache is working normally."""

_CDN_LOGS = """\
[2024-03-15T12:15:00Z] INFO  cdn/config_manager.go:89 DNS configuration update applied: updated CNAME records for static.example.com
[2024-03-15T12:15:01Z] INFO  cdn/config_manager.go:95 TTL propagation started (TTL=300s)
[2024-03-15T12:20:00Z] INFO  cdn/config_manager.go:102 TTL propagation complete. All edge nodes updated.
[2024-03-15T12:25:00Z] INFO  cdn/health.go:34 Post-change health check: all edge nodes responding normally
[2024-03-15T14:30:00Z] INFO  cdn/health.go:34 Routine health check: OK. Cache hit rate 98.7%.
NOTE: DNS config change was 2 hours ago. Fully propagated and verified. No current impact on any service."""

_SYSTEM_OVERVIEW = """\
System Overview — 2024-03-15T14:35:00Z

  Cluster: prod-us-east-1
  Total Services: 12
  Services Healthy: 9
  Services Degraded: 3 (api-gateway, auth-service, order-service)
  Services Warning: 1 (recommendation-service — CPU autoscale, non-critical)
  Services Down: 0

  Active Incidents:
    INC-2024-0315-001: Intermittent 500 errors across api-gateway
      Opened: 2024-03-15T14:15:00Z (20 min ago)
      Severity: SEV-2 (auto-classified)
      Affected: ~10% of authenticated requests
      Impact: Sporadic order failures, user-facing 502 errors
      On-call: @you

  Error Rate Trend (cluster-wide):
    14:00-14:10: 0.2% (baseline)
    14:10-14:15: 0.5% (initial elevation)
    14:15-14:20: 7.8% (spike)
    14:20-14:25: 8.3%
    14:25-14:30: 8.1%
    14:30-14:35: 8.0% (stable but elevated)

  Pattern Analysis:
    - Errors are NOT uniformly distributed across requests
    - Errors cluster around specific user sessions
    - No correlation with geographic region or client type
    - Some affected users succeed on retry (suggesting intermittent upstream issue)
    - Unaffected paths: /search, /recommendations, /static"""

_SYSTEM_RECENT_CHANGES = """\
Recent Changes (last 24 hours):

  1. [2024-03-15T14:10:00Z] auth-service v5.1.0-canary deployed (10% traffic)
     Change: Refactored OAuth token validation to use claims-validator v3
     Author: ci-bot (PR #2341 by @sarah-auth)
     Status: CANARY_ACTIVE

  2. [2024-03-15T12:15:00Z] cdn DNS configuration update
     Change: Updated CNAME records for static.example.com
     Author: @infra-bot (automated)
     Status: COMPLETED — propagated and verified

  3. [2024-03-15T06:00:00Z] database maintenance window
     Change: Routine vacuum and index rebuild (automated)
     Author: dba-automation
     Status: COMPLETED — no issues

  4. [2024-03-14T22:00:00Z] notification-service config update
     Change: Adjusted email retry backoff from 30s to 60s
     Author: @alerts-team
     Status: COMPLETED

  5. [2024-03-14T16:00:00Z] queue scaling event
     Change: Increased partition count from 12 to 16 for order-events topic
     Author: @platform-team
     Status: COMPLETED

  NOTE: provider-B had a brief JWKS endpoint outage on 2024-03-10 (5 days ago)
  lasting 45 minutes. Fully resolved. All tokens issued since then are valid.
  Current provider-B status: HEALTHY."""

_SYSTEM_DEPENDENCY_GRAPH = """\
Service Dependency Graph:

  api-gateway
    ├── auth-service (authentication for all /api/* routes)
    │     ├── database (session store, revocation lists)
    │     └── cache (token cache, JWKS key cache)
    ├── user-service
    │     └── database
    ├── payment-service
    │     ├── database
    │     └── notification-service
    │           └── queue
    ├── order-service
    │     ├── auth-service (validates user tokens)
    │     └── database
    └── search-service (no auth required for read-only search)

  recommendation-service (standalone, async — does NOT depend on auth)
  cdn (edge layer, serves static assets only)

  Critical Path: api-gateway → auth-service → database
  Note: auth-service is a single point of authentication for all services
  that require user identity. If auth-service is degraded, all authenticated
  endpoints are affected."""

_USER_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  user-service/handler.go:45 GET /users/usr_28471/profile status=200 latency_ms=42
[2024-03-15T14:33:00Z] INFO  user-service/handler.go:45 GET /users/usr_44192/profile status=200 latency_ms=55
[2024-03-15T14:34:00Z] INFO  user-service/handler.go:45 GET /users/usr_33918/settings status=200 latency_ms=38
NOTE: user-service is healthy. All requests succeeding normally. Database queries nominal."""

_PAYMENT_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  payment-service/handler.go:78 Payment processed payment_id=pay_44291 user_id=usr_55301 amount=18.50 status=SUCCESS
[2024-03-15T14:33:00Z] INFO  payment-service/handler.go:78 Payment processed payment_id=pay_44292 user_id=usr_33918 amount=127.00 status=SUCCESS
[2024-03-15T14:34:00Z] WARN  payment-service/handler.go:91 Payment auth pre-check failed user_id=usr_82156 — upstream auth-service 500 (will retry)
[2024-03-15T14:34:01Z] INFO  payment-service/handler.go:78 Payment processed payment_id=pay_44293 user_id=usr_82156 amount=65.20 status=SUCCESS (retry succeeded)
NOTE: payment-service itself is healthy. Occasional failures are auth-service passthrough errors."""

_NOTIFICATION_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  notification-service/sender.go:89 Email sent to usr_28471@example.com template=order_confirmation
[2024-03-15T14:33:00Z] WARN  notification-service/sender.go:112 Email delivery delayed: SMTP server slow response (1200ms vs 200ms baseline)
[2024-03-15T14:33:01Z] INFO  notification-service/sender.go:89 Email sent to usr_44192@example.com template=password_reset
[2024-03-15T14:34:00Z] INFO  notification-service/sender.go:89 Email sent to usr_33918@example.com template=order_confirmation
NOTE: notification-service is healthy. One slow SMTP response is within normal variance. Not related to auth errors."""

_SEARCH_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  search-service/handler.go:56 Search query="bluetooth headphones" results=142 latency_ms=72
[2024-03-15T14:33:00Z] INFO  search-service/handler.go:56 Search query="usb-c cable" results=89 latency_ms=65
[2024-03-15T14:34:00Z] INFO  search-service/handler.go:56 Search query="mechanical keyboard" results=234 latency_ms=81
NOTE: search-service is fully healthy. Does not depend on auth-service."""

_QUEUE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  kafka/broker.go:134 Partition rebalance complete for topic=order-events (16 partitions)
[2024-03-15T14:33:00Z] INFO  kafka/broker.go:145 Consumer lag: topic=order-events avg_lag=12 max_lag=45 (nominal)
[2024-03-15T14:34:00Z] INFO  kafka/broker.go:145 Consumer lag: topic=order-events avg_lag=10 max_lag=38 (nominal)
NOTE: Queue is healthy. Recent partition increase (16 partitions) absorbed smoothly."""


# ---------------------------------------------------------------------------
# Scenario class
# ---------------------------------------------------------------------------

class HardCanaryScenario(BaseScenario):
    """Intermittent Canary Deployment with Correlated Failures.

    auth-service is running a 90/10 canary deployment of v5.1.0-canary.
    The new version's claims parser rejects provider-B OAuth tokens due to
    a non-standard nested_permissions claim. Only ~10% of traffic hits the
    canary, and only ~10% of users authenticate via provider-B, making the
    effective error rate ~8% — high enough to be noticeable, low enough to
    be confusing. The errors cascade through order-service and api-gateway.

    Red herrings:
    - recommendation-service has a CPU spike (scheduled ML job, autoscaler
      responding, zero user impact).
    - cdn had a DNS config change 2 hours ago (fully resolved).
    - provider-B had a brief outage 5 days ago (fully resolved).
    """

    task_id = "hard_canary"
    name = "Intermittent Canary Deployment Regression"
    difficulty = "hard"
    description = (
        "Intermittent 500 errors affecting ~10% of authenticated requests. "
        "Multiple services showing degradation. recommendation-service CPU "
        "alert firing. Root cause is subtle and requires correlating deployment "
        "history, per-pod metrics, and OAuth provider patterns."
    )

    time_budget = 180
    max_steps = 35

    time_costs = {
        "investigate": 12,
        "diagnose": 8,
        "act": 25,
        "escalate": 5,
    }

    root_cause = (
        "auth-service v5.1.0-canary has OAuth provider-B token validation "
        "bug in new claims parser — the claims-validator v3 library rejects "
        "provider-B's non-standard nested_permissions claim structure"
    )

    root_cause_keywords: Set[str] = {
        "canary",
        "auth-service",
        "provider-b",
        "oauth",
        "canary deployment",
        "v5.1.0",
        "claims",
        "token",
        "nested_permissions",
        "claims-validator",
    }

    optimal_actions: List[str] = [
        "rollback auth-service",
        "kill_canary auth-service",
    ]

    initial_alert = (
        "ANOMALY DETECTED — INC-2024-0315-001\n"
        "Severity: SEV-2 (auto-classified)\n"
        "Summary: Intermittent HTTP 500 errors across api-gateway. Error rate "
        "spiked from 0.1% to ~8% starting 25 minutes ago. Affects approximately "
        "10% of authenticated requests — pattern is sporadic and not uniformly "
        "distributed. order-service also reporting elevated error rate (7.2%). "
        "recommendation-service CPU alert firing (92% utilization).\n"
        "Impact: Sporadic failures for order creation, payment processing, and "
        "user profile access. Some users succeed on retry.\n"
        "On-call: You are the primary responder.\n"
        "Hint: Errors do not correlate with request volume, geographic region, "
        "or client type. Some users are consistently affected while others are not."
    )

    def __init__(self) -> None:
        self.services = self._build_services()
        self.investigation_results = self._build_investigation_results()
        self.red_herrings = self._build_red_herrings()
        self.cascading_effects = self._build_cascading_effects()
        self.relevant_investigations = self._build_relevant_investigations()

    # -- Abstract method implementations ------------------------------------

    def create_initial_state(self) -> IncidentState:
        return IncidentState(
            episode_id=str(uuid4()),
            step_count=0,
            task_id=self.task_id,
            difficulty=self.difficulty,
            root_cause=self.root_cause,
            optimal_actions=self.optimal_actions,
            time_elapsed=0,
            time_budget=self.time_budget,
            max_steps=self.max_steps,
            services_status={
                name: svc.status for name, svc in self.services.items()
            },
        )

    def create_initial_observation(self) -> IncidentObservation:
        return IncidentObservation(
            message=self.initial_alert,
            alert_summary=(
                "Intermittent 500s on api-gateway (~8% error rate). "
                "order-service also degraded. recommendation-service CPU alert. "
                "~10% of authenticated requests failing. Started 25 min ago."
            ),
            system_status=self.get_system_status_dict(),
            available_actions=self.get_available_actions(),
            time_elapsed=0,
            time_budget=self.time_budget,
            done=False,
            reward=0.0,
            metadata={
                "scenario_id": self.task_id,
                "task_id": self.task_id,
                "difficulty": self.difficulty,
                "max_steps": self.max_steps,
            },
        )

    def score_resolution(self, actions_taken: List[str]) -> float:
        """Score the agent's corrective actions.

        Scoring tiers:
        - 1.0: Rolled back or killed canary on auth-service
        - 0.5: Restarted auth-service (temporary fix, doesn't address canary)
        - 0.3: Correctly identified auth-service but took wrong action
        - 0.2: Acted on recommendation-service (fell for red herring)
        - 0.1: Acted on order-service or api-gateway (treated symptom)
        - 0.0: No meaningful action or completely wrong target
        """
        actions_lower = [a.lower() for a in actions_taken]

        # Best outcome: rollback or kill_canary on auth-service
        for action in actions_lower:
            if ("rollback" in action or "kill_canary" in action) and "auth-service" in action:
                return 1.0

        # Partial: restart auth-service (helps temporarily but canary restarts too)
        for action in actions_lower:
            if "restart" in action and "auth-service" in action:
                return 0.5

        # Partial: targeted auth-service but wrong action (scale_up, flush_cache, etc.)
        for action in actions_lower:
            if "auth-service" in action and any(
                cmd in action
                for cmd in ("scale_up", "scale_down", "flush_cache", "drain_connections", "failover")
            ):
                return 0.3

        # Red herring: targeted recommendation-service
        for action in actions_lower:
            if "recommendation-service" in action:
                return 0.2

        # Symptom treatment: targeted order-service or api-gateway
        for action in actions_lower:
            if "order-service" in action or "api-gateway" in action:
                return 0.1

        return 0.0

    # -- Service definitions ------------------------------------------------

    @staticmethod
    def _build_services() -> Dict[str, ServiceInfo]:
        return {
            "api-gateway": ServiceInfo(
                name="api-gateway",
                status="degraded",
                latency_ms=1200,
                error_rate=0.081,
                cpu_pct=45.2,
                memory_pct=40.8,
                dependencies=["auth-service", "user-service", "payment-service",
                               "order-service", "search-service"],
            ),
            "auth-service": ServiceInfo(
                name="auth-service",
                status="degraded",
                latency_ms=800,
                error_rate=0.082,
                cpu_pct=50.1,
                memory_pct=45.3,
                dependencies=["database", "cache"],
            ),
            "user-service": ServiceInfo(
                name="user-service",
                status="healthy",
                latency_ms=60,
                error_rate=0.003,
                cpu_pct=30.0,
                memory_pct=35.0,
                dependencies=["database"],
            ),
            "payment-service": ServiceInfo(
                name="payment-service",
                status="healthy",
                latency_ms=120,
                error_rate=0.005,
                cpu_pct=35.0,
                memory_pct=40.0,
                dependencies=["database", "notification-service"],
            ),
            "order-service": ServiceInfo(
                name="order-service",
                status="degraded",
                latency_ms=900,
                error_rate=0.072,
                cpu_pct=32.4,
                memory_pct=38.1,
                dependencies=["auth-service", "database"],
            ),
            "search-service": ServiceInfo(
                name="search-service",
                status="healthy",
                latency_ms=80,
                error_rate=0.002,
                cpu_pct=25.0,
                memory_pct=30.0,
                dependencies=[],
            ),
            "notification-service": ServiceInfo(
                name="notification-service",
                status="healthy",
                latency_ms=100,
                error_rate=0.003,
                cpu_pct=18.0,
                memory_pct=25.0,
                dependencies=["queue"],
            ),
            "recommendation-service": ServiceInfo(
                name="recommendation-service",
                status="warning",
                latency_ms=200,
                error_rate=0.010,
                cpu_pct=92.3,
                memory_pct=55.1,
                dependencies=[],
            ),
            "database": ServiceInfo(
                name="database",
                status="healthy",
                latency_ms=8,
                error_rate=0.001,
                cpu_pct=45.0,
                memory_pct=50.2,
                dependencies=[],
            ),
            "cache": ServiceInfo(
                name="cache",
                status="healthy",
                latency_ms=3,
                error_rate=0.0,
                cpu_pct=12.4,
                memory_pct=28.0,
                dependencies=[],
            ),
            "queue": ServiceInfo(
                name="queue",
                status="healthy",
                latency_ms=10,
                error_rate=0.0,
                cpu_pct=8.0,
                memory_pct=15.0,
                dependencies=[],
            ),
            "cdn": ServiceInfo(
                name="cdn",
                status="healthy",
                latency_ms=25,
                error_rate=0.001,
                cpu_pct=5.0,
                memory_pct=10.0,
                dependencies=[],
            ),
        }

    # -- Investigation data -------------------------------------------------

    @staticmethod
    def _build_investigation_results() -> Dict[Tuple[str, str], str]:
        return {
            # auth-service — the core of the incident
            ("auth-service", "logs"): _AUTH_LOGS,
            ("auth-service", "metrics"): _AUTH_METRICS,
            ("auth-service", "deployments"): _AUTH_DEPLOYMENTS,
            ("auth-service", "dependencies"): _AUTH_DEPENDENCIES,
            ("auth-service", "config"): _AUTH_CONFIG,

            # order-service — victim / downstream
            ("order-service", "logs"): _ORDER_LOGS,
            ("order-service", "metrics"): _ORDER_METRICS,
            ("order-service", "deployments"): (
                "Deployment History for order-service:\n"
                "  v4.2.1 (current) — deployed 2024-03-07T10:00:00Z (8 days ago)\n"
                "    Changes: \"Improved order validation error messages\"\n"
                "    Status: STABLE — no recent changes"
            ),
            ("order-service", "dependencies"): (
                "Service: order-service\n"
                "  Upstream: api-gateway\n"
                "  Downstream:\n"
                "    - auth-service: DEGRADED (intermittent 500s)\n"
                "    - database: HEALTHY"
            ),

            # api-gateway — victim / entry point
            ("api-gateway", "logs"): _API_GATEWAY_LOGS,
            ("api-gateway", "metrics"): _API_GATEWAY_METRICS,
            ("api-gateway", "deployments"): _API_GATEWAY_DEPLOYMENTS,
            ("api-gateway", "dependencies"): (
                "Service: api-gateway\n"
                "  Upstream: external clients (internet)\n"
                "  Downstream:\n"
                "    - auth-service: DEGRADED (intermittent 500s — source of errors)\n"
                "    - user-service: HEALTHY\n"
                "    - payment-service: HEALTHY\n"
                "    - order-service: DEGRADED (cascading from auth)\n"
                "    - search-service: HEALTHY"
            ),

            # user-service — healthy bystander
            ("user-service", "logs"): _USER_SERVICE_LOGS,
            ("user-service", "metrics"): (
                "Service: user-service\n"
                "  p50_latency_ms: 42\n  p99_latency_ms: 60\n"
                "  error_rate_5xx: 0.003\n  request_rate_rps: 1800\n"
                "  cpu_utilization_pct: 30.0\n  memory_utilization_pct: 35.0\n"
                "NOTE: All metrics nominal."
            ),
            ("user-service", "deployments"): (
                "Deployment History for user-service:\n"
                "  v6.1.0 (current) — deployed 2024-03-06T14:00:00Z (9 days ago)\n"
                "    Changes: \"Added pagination support for user list endpoint\"\n"
                "    Status: STABLE"
            ),

            # payment-service — healthy, occasional auth passthrough errors
            ("payment-service", "logs"): _PAYMENT_SERVICE_LOGS,
            ("payment-service", "metrics"): (
                "Service: payment-service\n"
                "  p50_latency_ms: 85\n  p99_latency_ms: 120\n"
                "  error_rate_5xx: 0.005\n  request_rate_rps: 650\n"
                "  cpu_utilization_pct: 35.0\n  memory_utilization_pct: 40.0\n"
                "NOTE: Healthy. Rare errors are auth-service passthrough."
            ),
            ("payment-service", "deployments"): (
                "Deployment History for payment-service:\n"
                "  v3.9.2 (current) — deployed 2024-03-04T11:00:00Z (11 days ago)\n"
                "    Changes: \"PCI compliance audit logging improvements\"\n"
                "    Status: STABLE"
            ),

            # notification-service — healthy
            ("notification-service", "logs"): _NOTIFICATION_SERVICE_LOGS,
            ("notification-service", "metrics"): (
                "Service: notification-service\n"
                "  p50_latency_ms: 55\n  p99_latency_ms: 100\n"
                "  error_rate_5xx: 0.003\n  request_rate_rps: 420\n"
                "  cpu_utilization_pct: 18.0\n  memory_utilization_pct: 25.0\n"
                "NOTE: Healthy. One slow SMTP response is normal variance."
            ),

            # search-service — healthy, no auth dependency
            ("search-service", "logs"): _SEARCH_SERVICE_LOGS,
            ("search-service", "metrics"): (
                "Service: search-service\n"
                "  p50_latency_ms: 68\n  p99_latency_ms: 80\n"
                "  error_rate_5xx: 0.002\n  request_rate_rps: 5400\n"
                "  cpu_utilization_pct: 25.0\n  memory_utilization_pct: 30.0\n"
                "NOTE: Fully healthy. Does not require authentication."
            ),

            # database — healthy
            ("database", "logs"): _DATABASE_LOGS,
            ("database", "metrics"): _DATABASE_METRICS,
            ("database", "deployments"): (
                "Deployment History for database:\n"
                "  PostgreSQL 15.4 — no application-level deployments\n"
                "  Last maintenance: 2024-03-15T06:00:00Z (routine vacuum)\n"
                "  Status: STABLE"
            ),

            # cache — healthy
            ("cache", "logs"): _CACHE_LOGS,
            ("cache", "metrics"): _CACHE_METRICS,

            # queue — healthy
            ("queue", "logs"): _QUEUE_LOGS,
            ("queue", "metrics"): (
                "Service: queue (Kafka 3.6)\n"
                "  latency_ms: 10\n  error_rate: 0.000\n"
                "  consumer_lag_avg: 12\n  consumer_lag_max: 45\n"
                "  partitions: 16\n  cpu_utilization_pct: 8.0\n"
                "  memory_utilization_pct: 15.0\n"
                "NOTE: Healthy. Recent partition increase absorbed."
            ),

            # System-level investigations
            ("system", "overview"): _SYSTEM_OVERVIEW,
            ("system", "recent_changes"): _SYSTEM_RECENT_CHANGES,
            ("system", "dependency_graph"): _SYSTEM_DEPENDENCY_GRAPH,
        }

    # -- Red herrings -------------------------------------------------------

    @staticmethod
    def _build_red_herrings() -> Dict[Tuple[str, str], str]:
        return {
            ("recommendation-service", "logs"): _RECOMMENDATION_LOGS,
            ("recommendation-service", "metrics"): _RECOMMENDATION_METRICS,
            ("recommendation-service", "deployments"): _RECOMMENDATION_DEPLOYMENTS,
            ("recommendation-service", "dependencies"): (
                "Service: recommendation-service\n"
                "  Upstream: api-gateway (async, non-blocking)\n"
                "  Downstream: None (standalone ML service, reads from data-lake)\n"
                "  Note: recommendation-service does NOT depend on auth-service.\n"
                "  It serves recommendations without requiring authentication."
            ),
            ("recommendation-service", "config"): (
                "Service: recommendation-service — Runtime Configuration\n"
                "  model_retraining_schedule: '0 14 * * *' (daily at 14:00 UTC)\n"
                "  autoscaler_enabled: true\n"
                "  autoscaler_min_replicas: 3\n"
                "  autoscaler_max_replicas: 8\n"
                "  autoscaler_target_cpu: 70\n"
                "  current_replicas: 5 (scaled at 14:30Z)\n"
                "NOTE: CPU spike is expected behavior during daily retraining."
            ),
            ("cdn", "logs"): _CDN_LOGS,
            ("cdn", "metrics"): (
                "Service: cdn\n"
                "  latency_ms: 25\n  error_rate: 0.001\n"
                "  cache_hit_rate_pct: 98.7\n"
                "  cpu_utilization_pct: 5.0\n  memory_utilization_pct: 10.0\n"
                "  dns_config_change: 2024-03-15T12:15:00Z (2 hours ago, fully propagated)\n"
                "NOTE: CDN is healthy. DNS change is fully resolved."
            ),
            ("cdn", "deployments"): (
                "Deployment History for cdn:\n"
                "  No application deployments. Infrastructure-managed.\n"
                "  Last config change: DNS CNAME update at 12:15Z (resolved)."
            ),
        }

    # -- Cascading effects --------------------------------------------------

    @staticmethod
    def _build_cascading_effects() -> List[CascadingEffect]:
        return [
            CascadingEffect(
                time_threshold=60,
                service="order-service",
                effect="down",
                description=(
                    "ESCALATION: order-service is now DOWN. Auth failures have "
                    "exhausted the retry budget and circuit breaker has tripped. "
                    "All order creation is failing."
                ),
            ),
            CascadingEffect(
                time_threshold=100,
                service="api-gateway",
                effect="degraded",
                description=(
                    "ESCALATION: api-gateway error rate has spiked to 15%. "
                    "Cascading auth failures are now affecting all authenticated "
                    "endpoints. Load balancer health checks are flagging instances."
                ),
            ),
            CascadingEffect(
                time_threshold=140,
                service="payment-service",
                effect="degraded",
                description=(
                    "ESCALATION: payment-service is now DEGRADED. Auth pre-check "
                    "failures are causing payment authorization to fail. Revenue "
                    "impact detected. Finance team auto-paged."
                ),
            ),
            CascadingEffect(
                time_threshold=170,
                service="user-service",
                effect="degraded",
                description=(
                    "ESCALATION: user-service is now DEGRADED. Profile and settings "
                    "endpoints returning errors for users whose auth tokens cannot "
                    "be validated. Support ticket volume spiking."
                ),
            ),
        ]

    # -- Relevant investigations (for efficiency scoring) -------------------

    @staticmethod
    def _build_relevant_investigations() -> Set[Tuple[str, str]]:
        return {
            ("auth-service", "logs"),
            ("auth-service", "metrics"),
            ("auth-service", "deployments"),
            ("auth-service", "config"),
            ("auth-service", "dependencies"),
            ("order-service", "logs"),
            ("order-service", "metrics"),
            ("order-service", "dependencies"),
            ("api-gateway", "logs"),
            ("api-gateway", "metrics"),
            ("api-gateway", "dependencies"),
            ("system", "overview"),
            ("system", "recent_changes"),
            ("system", "dependency_graph"),
        }
