"""Hard scenario: Intermittent Canary Deployment with Correlated Failures.

auth-service is running a 90/10 canary deployment. The canary version
(v5.1.0-canary) has a subtle bug in the new OAuth claims parser that fails
ONLY for tokens issued by provider-B (~10% of users). Meanwhile,
recommendation-service has an unrelated CPU spike from a scheduled ML
retraining job, config-service recently pushed a config update to several
services, database has a suspicious-looking slow query, payment-service has
a certificate renewal warning, and search-service shows elevated cache miss
rate.

The result is that ~8% of overall auth requests fail (10% canary traffic x
~80% provider-B failure rate on canary pod). This cascades through
order-service and api-gateway because they depend on auth-service.

The agent must:
1. Notice the intermittent 500s are not uniformly distributed.
2. Trace the errors to auth-service (not recommendation-service or config-service).
3. Discover the canary deployment and the per-pod error breakdown.
4. Correlate failures with provider-B tokens on the canary pod.
5. Roll back the canary (or kill it) to resolve the incident.

The first time auth-service logs are checked, they appear mostly clean.
The agent must dig deeper (re-check or check metrics/deployments) to
discover the real issue.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple
from uuid import uuid4

from incident_env.models import IncidentObservation, IncidentState
from incident_env.scenarios.base import BaseScenario, CascadingEffect, ServiceInfo


# ---------------------------------------------------------------------------
# Log / metric text blocks
# ---------------------------------------------------------------------------

# First-time auth-service logs: MOSTLY clean. Only 2 subtle errors buried
# among 30+ success lines. Errors do NOT mention provider-B explicitly.
_AUTH_LOGS_FIRST_CHECK = """\
[2024-03-15T14:32:01Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_20184 status=ok latency_ms=11 pod=auth-stable-7b4f9
[2024-03-15T14:32:01Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_44920 status=ok latency_ms=9 pod=auth-stable-a3m8k
[2024-03-15T14:32:02Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_38127 status=ok latency_ms=13 pod=auth-stable-7b4f9
[2024-03-15T14:32:02Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_72841 status=ok latency_ms=10 pod=auth-canary-x9k2m
[2024-03-15T14:32:03Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_55301 status=ok latency_ms=15 pod=auth-stable-a3m8k
[2024-03-15T14:32:03Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_73219 status=ok latency_ms=8 pod=auth-canary-x9k2m
[2024-03-15T14:32:04Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_12847 status=ok latency_ms=11 pod=auth-stable-7b4f9
[2024-03-15T14:32:04Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_33918 status=ok latency_ms=9 pod=auth-stable-7b4f9
[2024-03-15T14:32:05Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_28471 status=ok latency_ms=12 pod=auth-stable-a3m8k
[2024-03-15T14:32:05Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_61845 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:32:06Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_90184 status=ok latency_ms=12 pod=auth-stable-7b4f9
[2024-03-15T14:32:06Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_48271 status=ok latency_ms=9 pod=auth-stable-a3m8k
[2024-03-15T14:32:07Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_52093 status=ok latency_ms=14 pod=auth-stable-7b4f9
[2024-03-15T14:32:07Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_19472 status=ok latency_ms=7 pod=auth-stable-a3m8k
[2024-03-15T14:32:08Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_44192 status=ok latency_ms=8 pod=auth-canary-x9k2m
[2024-03-15T14:32:08Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_73891 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:32:09Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_88214 status=ok latency_ms=11 pod=auth-stable-a3m8k
[2024-03-15T14:32:09Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_91823 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:32:10Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_66501 status=ok latency_ms=9 pod=auth-stable-7b4f9
[2024-03-15T14:32:10Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_33782 status=ok latency_ms=13 pod=auth-stable-a3m8k
[2024-03-15T14:32:11Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_42918 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:32:11Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_77341 status=ok latency_ms=8 pod=auth-stable-a3m8k
[2024-03-15T14:32:12Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_29104 status=ok latency_ms=12 pod=auth-stable-7b4f9
[2024-03-15T14:32:12Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_51283 status=ok latency_ms=7 pod=auth-canary-x9k2m
[2024-03-15T14:32:13Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_84629 status=ok latency_ms=11 pod=auth-stable-a3m8k
[2024-03-15T14:32:13Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_37104 status=ok latency_ms=14 pod=auth-stable-7b4f9
[2024-03-15T14:32:14Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_67234 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:32:14Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_95127 status=ok latency_ms=9 pod=auth-stable-a3m8k
[2024-03-15T14:32:15Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_18493 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:32:15Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_62817 status=ok latency_ms=8 pod=auth-stable-a3m8k"""

# Second-time auth-service logs: more errors visible, shows the pattern
# more clearly. Still no explicit "provider-B" label — just more error lines
# on the canary pod. Agent needs to correlate with deployment/config.
_AUTH_LOGS_SECOND_CHECK = """\
[2024-03-15T14:35:01Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_20184 status=ok latency_ms=11 pod=auth-stable-7b4f9
[2024-03-15T14:35:01Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_83921 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:35:02Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_38127 status=ok latency_ms=13 pod=auth-stable-7b4f9
[2024-03-15T14:35:02Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_47182 status=fail error="claim structure mismatch: unexpected nested field in realm_access" pod=auth-canary-x9k2m
[2024-03-15T14:35:03Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_55301 status=ok latency_ms=15 pod=auth-stable-a3m8k
[2024-03-15T14:35:03Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_73219 status=ok latency_ms=8 pod=auth-canary-x9k2m
[2024-03-15T14:35:04Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_91823 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:35:04Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_12847 status=ok latency_ms=11 pod=auth-stable-7b4f9
[2024-03-15T14:35:05Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_33918 status=ok latency_ms=9 pod=auth-stable-7b4f9
[2024-03-15T14:35:05Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_67234 status=fail error="claim structure mismatch: unexpected nested field in realm_access" pod=auth-canary-x9k2m
[2024-03-15T14:35:06Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_28471 status=ok latency_ms=12 pod=auth-stable-a3m8k
[2024-03-15T14:35:06Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_82156 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:35:07Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_61845 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:35:07Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_90184 status=ok latency_ms=12 pod=auth-stable-7b4f9
[2024-03-15T14:35:08Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_16392 status=fail error="claim structure mismatch: unexpected nested field in realm_access" pod=auth-canary-x9k2m
[2024-03-15T14:35:08Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_48271 status=ok latency_ms=9 pod=auth-stable-a3m8k
[2024-03-15T14:35:09Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_52093 status=ok latency_ms=14 pod=auth-stable-7b4f9
[2024-03-15T14:35:09Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_39471 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:35:10Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_19472 status=ok latency_ms=7 pod=auth-stable-a3m8k
[2024-03-15T14:35:10Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_73891 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:35:11Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_58214 status=fail error="claim structure mismatch: unexpected nested field in realm_access" pod=auth-canary-x9k2m
[2024-03-15T14:35:11Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_44192 status=ok latency_ms=8 pod=auth-canary-x9k2m
[2024-03-15T14:35:12Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_33782 status=ok latency_ms=13 pod=auth-stable-a3m8k
[2024-03-15T14:35:12Z] ERROR auth-service/handler.go:112 token_validation user_id=usr_71029 status=fail error="claim structure mismatch" pod=auth-canary-x9k2m
[2024-03-15T14:35:13Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_42918 status=ok latency_ms=10 pod=auth-stable-7b4f9
[2024-03-15T14:35:13Z] INFO  auth-service/handler.go:89  token_validation user_id=usr_84629 status=ok latency_ms=11 pod=auth-stable-a3m8k"""

# Auth-service metrics: shows per-pod breakdown but NO per-provider breakdown.
# The agent can see canary pod has higher errors but not WHY.
_AUTH_METRICS = """\
Service: auth-service
  Replicas: 3 (2 stable + 1 canary)
  Overall Metrics (last 15 min):
    p50_latency_ms: 45
    p95_latency_ms: 320
    p99_latency_ms: 800
    error_rate_5xx: 0.082
    request_rate_rps: 2400
    success_rate: 91.8%
    cpu_utilization_pct: 50.1
    memory_utilization_pct: 45.3
    active_connections: 4812
    connection_pool_usage_pct: 62.0

  Per-Pod Breakdown:
    auth-stable-7b4f9 (~45% traffic):
      error_rate_5xx: 0.001
      request_rate_rps: 1080
      p99_latency_ms: 88
      cpu_utilization_pct: 38.2
      memory_utilization_pct: 42.0

    auth-stable-a3m8k (~45% traffic):
      error_rate_5xx: 0.001
      request_rate_rps: 1080
      p99_latency_ms: 92
      cpu_utilization_pct: 39.7
      memory_utilization_pct: 43.1

    auth-canary-x9k2m (~10% traffic):
      error_rate_5xx: 0.82
      request_rate_rps: 240
      p99_latency_ms: 1850
      cpu_utilization_pct: 78.4
      memory_utilization_pct: 52.1"""

_AUTH_DEPLOYMENTS = """\
Deployment History for auth-service:

  v5.1.0-canary -- deployed 2024-03-15T14:10:00Z (25 min ago) by ci-bot
    Commit: 7a8b9c0 -- "migrate to structured claims validation library v3"
    PR: #2341 -- "Upgrade claims parsing for provider compliance"
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
    Status: CANARY_ACTIVE -- promotion blocked (error threshold exceeded)

  v5.0.4 (stable) -- deployed 2024-03-10T08:00:00Z (5 days ago) by ci-bot
    Commit: 3d4e5f6 -- "add structured logging for OAuth provider metrics"
    Changes: Minor logging improvements, no behavioral changes
    Status: STABLE
    Pods: auth-stable-7b4f9, auth-stable-a3m8k

  v5.0.3 -- deployed 2024-03-03T14:30:00Z (12 days ago)
    Changes: Rate limiter tuning (increased quota from 500 to 800 rps)
    Status: SUPERSEDED

  v5.0.2 -- deployed 2024-02-28T10:00:00Z (16 days ago)
    Changes: Fixed connection pool leak on timeout path
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

  OAuth Providers (external):
    - provider-A: HEALTHY (last checked 2min ago)
    - provider-B: HEALTHY (last checked 2min ago)
    - provider-C: HEALTHY (last checked 2min ago)"""

# Config reveals the critical info: claims_validation_mode changed, legacy
# fallback disabled. This is where provider-B's non-standard claim becomes
# relevant. But the agent has to READ this and connect the dots.
_AUTH_CONFIG = """\
Service: auth-service -- Runtime Configuration

  Canary Configuration:
    canary_enabled: true
    canary_version: v5.1.0-canary
    canary_traffic_pct: 10
    canary_pod_selector: "app=auth-service,track=canary"
    canary_auto_promote: true
    canary_promote_after: 7200
    canary_error_threshold: 0.01
    canary_rollback_on_breach: false

  Token Validation Config:
    token_cache_ttl_sec: 300
    max_token_age_sec: 3600
    supported_providers: [provider-A, provider-B, provider-C]
    claims_validation_mode: "strict"   # changed in v5.1.0 from "permissive"
    nested_claims_support: true        # new in v5.1.0
    legacy_parser_fallback: false      # disabled in v5.1.0 (was true in v5.0.4)

  Provider Token Formats:
    provider-A: standard JWT (RFC 7519 compliant)
    provider-B: JWT with non-standard nested_permissions in realm_access claim
    provider-C: standard JWT (RFC 7519 compliant)

  Rate Limiting:
    per_provider_rps_limit: 800
    global_rps_limit: 3000
    burst_allowance: 1.5x

  Circuit Breaker:
    enabled: true
    error_threshold_pct: 50
    window_sec: 60
    half_open_after_sec: 30
    state: CLOSED"""

_ORDER_LOGS = """\
[2024-03-15T14:33:01Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_91823 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:01Z] INFO  order-service/auth_client.go:72  auth validation ok on retry user_id=usr_91823 (retried to different pod)
[2024-03-15T14:33:02Z] INFO  order-service/handler.go:134 order created order_id=ord_88291 user_id=usr_44192 total=42.99
[2024-03-15T14:33:03Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_67234 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:03Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_67234 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:04Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_67234 status=500 upstream=auth-service retry=3/3
[2024-03-15T14:33:04Z] ERROR order-service/handler.go:141 order creation failed user_id=usr_67234 error="upstream auth-service returned 500 after 3 retries"
[2024-03-15T14:33:05Z] INFO  order-service/handler.go:134 order created order_id=ord_88292 user_id=usr_55301 total=18.50
[2024-03-15T14:33:06Z] INFO  order-service/handler.go:134 order created order_id=ord_88293 user_id=usr_33918 total=127.00
[2024-03-15T14:33:07Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_82156 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:07Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_82156 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:07Z] WARN  order-service/auth_client.go:78  auth validation ok on retry 3 user_id=usr_82156
[2024-03-15T14:33:08Z] INFO  order-service/handler.go:134 order created order_id=ord_88294 user_id=usr_82156 total=65.20
[2024-03-15T14:33:09Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_16392 status=500 upstream=auth-service retry=1/3
[2024-03-15T14:33:09Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_16392 status=500 upstream=auth-service retry=2/3
[2024-03-15T14:33:10Z] ERROR order-service/auth_client.go:67  auth validation failed user_id=usr_16392 status=500 upstream=auth-service retry=3/3
[2024-03-15T14:33:10Z] ERROR order-service/handler.go:141 order creation failed user_id=usr_16392 error="upstream auth-service returned 500 after 3 retries\""""

_ORDER_METRICS = """\
Service: order-service
  p50_latency_ms: 180
  p99_latency_ms: 900
  error_rate_5xx: 0.072
  request_rate_rps: 850
  cpu_utilization_pct: 32.4
  memory_utilization_pct: 38.1

  Error Breakdown:
    auth_validation_failures: 68%
    database_errors: 0%
    internal_errors: 2%
    timeout_errors: 30%

  Dependency Health (as seen by order-service):
    auth-service: DEGRADED (intermittent 500s)
    database: HEALTHY
    payment-service: HEALTHY"""

_API_GATEWAY_LOGS = """\
[2024-03-15T14:34:01Z] WARN  api-gateway/proxy.go:201 upstream error: status=500 service=auth-service request_id=req_a8f21 path=/api/v2/orders
[2024-03-15T14:34:01Z] INFO  api-gateway/proxy.go:189 request_id=req_b2c43 path=/api/v2/users/profile status=200 latency_ms=62
[2024-03-15T14:34:02Z] INFO  api-gateway/proxy.go:189 request_id=req_d4e65 path=/api/v2/search status=200 latency_ms=85
[2024-03-15T14:34:02Z] WARN  api-gateway/proxy.go:201 upstream error: status=500 service=auth-service request_id=req_f6g87 path=/api/v2/payments
[2024-03-15T14:34:03Z] INFO  api-gateway/proxy.go:189 request_id=req_h8i09 path=/api/v2/orders status=200 latency_ms=340
[2024-03-15T14:34:03Z] INFO  api-gateway/proxy.go:189 request_id=req_j0k12 path=/api/v2/users/settings status=200 latency_ms=55
[2024-03-15T14:34:04Z] ERROR api-gateway/proxy.go:215 request_id=req_l2m34 path=/api/v2/orders status=502 error="auth-service retries exhausted"
[2024-03-15T14:34:04Z] INFO  api-gateway/proxy.go:189 request_id=req_n4o56 path=/api/v2/recommendations status=200 latency_ms=210
[2024-03-15T14:34:05Z] INFO  api-gateway/proxy.go:189 request_id=req_p6q78 path=/api/v2/search status=200 latency_ms=79
[2024-03-15T14:34:05Z] INFO  api-gateway/proxy.go:189 request_id=req_r8s90 path=/api/v2/analytics/events status=200 latency_ms=42
[2024-03-15T14:34:06Z] WARN  api-gateway/proxy.go:201 upstream error: status=500 service=auth-service request_id=req_t1u23 path=/api/v2/orders
[2024-03-15T14:34:06Z] INFO  api-gateway/proxy.go:189 request_id=req_v4w56 path=/api/v2/billing/invoices status=200 latency_ms=95"""

_API_GATEWAY_METRICS = """\
Service: api-gateway
  p50_latency_ms: 120
  p95_latency_ms: 680
  p99_latency_ms: 1200
  error_rate_5xx: 0.081
  request_rate_rps: 12000
  cpu_utilization_pct: 45.2
  memory_utilization_pct: 40.8

  Error Breakdown by Upstream:
    auth-service: 95%
    order-service: 3%
    payment-service: 2%
    user-service: 0%
    search-service: 0%
    billing-service: 0%
    analytics-service: 0%"""

_API_GATEWAY_DEPLOYMENTS = """\
Deployment History for api-gateway:
  v3.8.2 (current) -- deployed 2024-03-08T12:00:00Z (7 days ago)
    Changes: "Upgrade HTTP/2 multiplexing, minor header parsing fix"
    Status: STABLE -- no recent changes"""

_RECOMMENDATION_LOGS = """\
[2024-03-15T14:28:00Z] INFO  recommendation-service/ml_pipeline.go:234 starting daily model retraining batch (scheduled cron: 0 14 * * *)
[2024-03-15T14:28:01Z] INFO  recommendation-service/ml_pipeline.go:240 loading training data from data-lake: 2.3M user interactions (last 7 days)
[2024-03-15T14:28:02Z] INFO  recommendation-service/ml_pipeline.go:256 feature extraction started, estimated duration: 25 min
[2024-03-15T14:28:15Z] INFO  recommendation-service/ml_pipeline.go:278 feature extraction progress: 12% (280K/2.3M records)
[2024-03-15T14:29:00Z] WARN  recommendation-service/resource_monitor.go:45 CPU utilization at 85%, approaching autoscale threshold (90%)
[2024-03-15T14:30:00Z] WARN  recommendation-service/resource_monitor.go:45 CPU utilization at 92%, autoscale threshold breached
[2024-03-15T14:30:01Z] INFO  recommendation-service/autoscaler.go:78 HPA triggered: scaling from 3 to 5 replicas (target CPU: 70%)
[2024-03-15T14:30:02Z] INFO  recommendation-service/autoscaler.go:92 new pods recommendation-svc-d7e8f, recommendation-svc-g9h0i starting
[2024-03-15T14:31:00Z] INFO  recommendation-service/autoscaler.go:105 pods ready, traffic rebalancing in progress
[2024-03-15T14:32:00Z] INFO  recommendation-service/health.go:45 health check passed, serving normally, p99_latency=195ms
[2024-03-15T14:33:00Z] INFO  recommendation-service/ml_pipeline.go:278 feature extraction progress: 48% (1.1M/2.3M records)
[2024-03-15T14:34:00Z] INFO  recommendation-service/resource_monitor.go:45 CPU utilization at 71% (post-scale), within target range"""

_RECOMMENDATION_METRICS = """\
Service: recommendation-service
  p50_latency_ms: 95
  p99_latency_ms: 200
  error_rate_5xx: 0.010
  request_rate_rps: 3200
  cpu_utilization_pct: 92.3
  memory_utilization_pct: 55.1
  replicas: 5 (scaled from 3 at 14:30Z)

  Autoscaler Status:
    trigger: CPU > 90% for 60s
    current_state: SCALING_COMPLETE
    target_cpu: 70%
    projected_cpu_after_scale: 55%"""

_RECOMMENDATION_DEPLOYMENTS = """\
Deployment History for recommendation-service:
  v2.14.0 (current) -- deployed 2024-03-05T09:00:00Z (10 days ago)
    Changes: "Updated feature store connector, improved caching for cold-start users"
    Status: STABLE -- no recent changes
  v2.13.8 -- deployed 2024-02-25T16:00:00Z
    Changes: "Bug fix: handle missing user preference data gracefully"
    Status: SUPERSEDED"""

# RED HERRING: database slow query
_DATABASE_LOGS = """\
[2024-03-15T14:10:22Z] INFO  postgresql/log: checkpoint starting: time
[2024-03-15T14:10:23Z] INFO  postgresql/log: checkpoint complete: wrote 847 buffers (0.6%)
[2024-03-15T14:14:45Z] WARN  postgresql/log: slow query: duration=852ms statement=SELECT u.id, u.email, u.created_at, p.plan_type, p.renewal_date, t.total_orders, t.total_revenue FROM users u JOIN plans p ON u.plan_id = p.id JOIN (SELECT user_id, COUNT(*) as total_orders, SUM(amount) as total_revenue FROM orders GROUP BY user_id) t ON u.id = t.user_id WHERE u.last_active > NOW() - INTERVAL '30 days' ORDER BY t.total_revenue DESC LIMIT 10000
[2024-03-15T14:14:46Z] INFO  postgresql/log: query originated from analytics-service (scheduled daily report, cron 14:14 UTC)
[2024-03-15T14:30:00Z] INFO  postgresql/log: automatic vacuum of table "auth_sessions": 1204 rows removed
[2024-03-15T14:32:00Z] INFO  postgresql/log: checkpoint starting: time
[2024-03-15T14:32:01Z] INFO  postgresql/log: checkpoint complete: wrote 312 buffers (0.2%)
[2024-03-15T14:33:00Z] INFO  postgresql/log: slow query: duration=45ms statement=SELECT * FROM token_revocations WHERE provider=$1 AND expires_at > NOW()
[2024-03-15T14:34:00Z] INFO  postgresql/log: connections: 142/500 active, 0 waiting"""

_DATABASE_METRICS = """\
Service: database (PostgreSQL 15.4)
  p50_latency_ms: 4
  p99_latency_ms: 12
  error_rate: 0.001
  connections_active: 142
  connections_max: 500
  cpu_utilization_pct: 48.0
  memory_utilization_pct: 52.3
  disk_io_pct: 28.0
  replication_lag_ms: 0
  lock_waits: 0
  deadlocks_last_hour: 0
  slow_queries_last_15min: 1 (852ms, analytics daily report)"""

_CACHE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  redis/server.go:312 memory usage: 1.2GB / 4GB (28%)
[2024-03-15T14:33:00Z] INFO  redis/server.go:318 key evictions last minute: 0
[2024-03-15T14:34:00Z] INFO  redis/server.go:324 hit rate: 94.2% (8412 hits / 8929 total)"""

_CACHE_METRICS = """\
Service: cache (Redis 7.2)
  latency_ms: 3
  error_rate: 0.000
  hit_rate_pct: 94.2
  memory_utilization_pct: 28.0
  connections_active: 89
  evictions_per_min: 0
  cpu_utilization_pct: 12.4"""

# RED HERRING: CDN DNS change (2 hours ago, resolved)
_CDN_LOGS = """\
[2024-03-15T12:15:00Z] INFO  cdn/config_manager.go:89 DNS configuration update applied: updated CNAME records for static.example.com
[2024-03-15T12:15:01Z] INFO  cdn/config_manager.go:95 TTL propagation started (TTL=300s)
[2024-03-15T12:20:00Z] INFO  cdn/config_manager.go:102 TTL propagation complete. All edge nodes updated.
[2024-03-15T12:25:00Z] INFO  cdn/health.go:34 post-change health check: all edge nodes responding normally
[2024-03-15T14:30:00Z] INFO  cdn/health.go:34 routine health check: OK, cache hit rate 98.7%"""

# RED HERRING: config-service pushed updates recently
_CONFIG_SERVICE_LOGS = """\
[2024-03-15T14:05:00Z] INFO  config-service/pusher.go:89 config push initiated by @platform-team
[2024-03-15T14:05:01Z] INFO  config-service/pusher.go:95 pushing updated rate-limit configs to: api-gateway, order-service, payment-service, auth-service
[2024-03-15T14:05:02Z] INFO  config-service/pusher.go:112 api-gateway acknowledged config update (rate_limit_global: 15000 -> 18000 rps)
[2024-03-15T14:05:02Z] INFO  config-service/pusher.go:112 order-service acknowledged config update (rate_limit_per_user: 50 -> 60 rps)
[2024-03-15T14:05:03Z] INFO  config-service/pusher.go:112 payment-service acknowledged config update (rate_limit_per_user: 30 -> 40 rps)
[2024-03-15T14:05:03Z] INFO  config-service/pusher.go:112 auth-service acknowledged config update (rate_limit_global: 2500 -> 3000 rps)
[2024-03-15T14:05:04Z] INFO  config-service/pusher.go:128 all 4 services acknowledged config push successfully
[2024-03-15T14:05:04Z] INFO  config-service/pusher.go:134 config version bumped: v142 -> v143
[2024-03-15T14:06:00Z] INFO  config-service/health.go:45 post-push health check: all target services report config v143 active
[2024-03-15T14:34:00Z] INFO  config-service/health.go:45 routine health check: OK"""

_CONFIG_SERVICE_METRICS = """\
Service: config-service
  p50_latency_ms: 12
  p99_latency_ms: 35
  error_rate_5xx: 0.000
  request_rate_rps: 120
  cpu_utilization_pct: 8.2
  memory_utilization_pct: 18.0
  last_push: 2024-03-15T14:05:04Z (30 min ago)
  last_push_targets: api-gateway, order-service, payment-service, auth-service
  last_push_status: SUCCESS
  config_version: v143"""

_CONFIG_SERVICE_DEPLOYMENTS = """\
Deployment History for config-service:
  v1.4.2 (current) -- deployed 2024-03-01T10:00:00Z (14 days ago)
    Changes: "Added audit logging for config pushes"
    Status: STABLE

  Recent Config Pushes (not code deployments):
    2024-03-15T14:05:04Z: rate-limit config update to 4 services (v142->v143)
    2024-03-14T09:00:00Z: feature-flag update to api-gateway (v141->v142)
    2024-03-12T16:00:00Z: timeout config update to order-service (v140->v141)"""

# RED HERRING: payment-service cert renewal warning
_PAYMENT_SERVICE_LOGS = """\
[2024-03-15T14:15:00Z] WARN  payment-service/tls_manager.go:78 TLS certificate for payment-gateway.internal will expire in 14 days (2024-03-29T00:00:00Z). Auto-renewal scheduled for 2024-03-22T00:00:00Z.
[2024-03-15T14:15:01Z] WARN  payment-service/tls_manager.go:82 mutual TLS cert for payment-processor.external renewal pending, current cert valid until 2024-03-29
[2024-03-15T14:32:00Z] INFO  payment-service/handler.go:78 payment processed payment_id=pay_44291 user_id=usr_55301 amount=18.50 status=SUCCESS
[2024-03-15T14:33:00Z] INFO  payment-service/handler.go:78 payment processed payment_id=pay_44292 user_id=usr_33918 amount=127.00 status=SUCCESS
[2024-03-15T14:34:00Z] WARN  payment-service/handler.go:91 payment auth pre-check failed user_id=usr_82156 -- upstream auth-service 500 (will retry)
[2024-03-15T14:34:01Z] INFO  payment-service/handler.go:78 payment processed payment_id=pay_44293 user_id=usr_82156 amount=65.20 status=SUCCESS (retry ok)
[2024-03-15T14:34:30Z] INFO  payment-service/handler.go:78 payment processed payment_id=pay_44294 user_id=usr_28471 amount=22.00 status=SUCCESS"""

_PAYMENT_SERVICE_METRICS = """\
Service: payment-service
  p50_latency_ms: 85
  p99_latency_ms: 120
  error_rate_5xx: 0.005
  request_rate_rps: 650
  cpu_utilization_pct: 35.0
  memory_utilization_pct: 40.0
  tls_cert_expiry_days: 14
  tls_auto_renewal: scheduled 2024-03-22"""

_PAYMENT_SERVICE_DEPLOYMENTS = """\
Deployment History for payment-service:
  v3.9.2 (current) -- deployed 2024-03-04T11:00:00Z (11 days ago)
    Changes: "PCI compliance audit logging improvements"
    Status: STABLE"""

# RED HERRING: search-service elevated cache miss rate
_SEARCH_SERVICE_LOGS = """\
[2024-03-15T14:30:00Z] INFO  search-service/cache.go:112 cache warm-up initiated after index rebuild (deployed v8.2.1 two days ago)
[2024-03-15T14:30:01Z] WARN  search-service/cache.go:118 cache hit rate dropped: 95.2% -> 78.4% during warm-up phase
[2024-03-15T14:30:02Z] INFO  search-service/cache.go:125 estimated warm-up completion: ~45 min (populating 12M entries)
[2024-03-15T14:32:00Z] INFO  search-service/handler.go:56 search query="bluetooth headphones" results=142 latency_ms=112 cache=MISS
[2024-03-15T14:32:30Z] INFO  search-service/handler.go:56 search query="usb-c cable" results=89 latency_ms=95 cache=MISS
[2024-03-15T14:33:00Z] INFO  search-service/handler.go:56 search query="mechanical keyboard" results=234 latency_ms=81 cache=HIT
[2024-03-15T14:33:30Z] INFO  search-service/cache.go:132 warm-up progress: 34% (4.1M/12M entries populated)
[2024-03-15T14:34:00Z] INFO  search-service/handler.go:56 search query="wireless mouse" results=167 latency_ms=102 cache=MISS"""

_SEARCH_SERVICE_METRICS = """\
Service: search-service
  p50_latency_ms: 95
  p99_latency_ms: 145
  error_rate_5xx: 0.002
  request_rate_rps: 5400
  cpu_utilization_pct: 38.0
  memory_utilization_pct: 42.0
  cache_hit_rate_pct: 78.4 (degraded -- warm-up in progress after index rebuild)
  normal_cache_hit_rate_pct: 95.2"""

# Billing service: healthy but minor cert warning (noise)
_BILLING_SERVICE_LOGS = """\
[2024-03-15T14:00:00Z] INFO  billing-service/handler.go:45 daily invoice generation batch started
[2024-03-15T14:01:00Z] INFO  billing-service/handler.go:52 generated 3,847 invoices for billing cycle 2024-03
[2024-03-15T14:01:01Z] INFO  billing-service/handler.go:58 invoice generation complete, sending to payment-service queue
[2024-03-15T14:15:00Z] WARN  billing-service/tls_manager.go:34 internal CA certificate expires in 30 days (2024-04-14). Renewal ticket: INFRA-8821
[2024-03-15T14:32:00Z] INFO  billing-service/handler.go:72 GET /billing/invoices/usr_28471 status=200 latency_ms=28
[2024-03-15T14:33:00Z] INFO  billing-service/handler.go:72 GET /billing/usage/usr_33918 status=200 latency_ms=31
[2024-03-15T14:34:00Z] INFO  billing-service/handler.go:72 GET /billing/invoices/usr_55301 status=200 latency_ms=25"""

_BILLING_SERVICE_METRICS = """\
Service: billing-service
  p50_latency_ms: 28
  p99_latency_ms: 55
  error_rate_5xx: 0.001
  request_rate_rps: 320
  cpu_utilization_pct: 15.0
  memory_utilization_pct: 22.0
  ca_cert_expiry_days: 30"""

# Analytics service: healthy, processing events normally
_ANALYTICS_SERVICE_LOGS = """\
[2024-03-15T14:14:45Z] INFO  analytics-service/batch.go:89 daily report query submitted to database
[2024-03-15T14:14:46Z] INFO  analytics-service/batch.go:95 report query completed in 852ms (10K rows, expected ~800ms for this report)
[2024-03-15T14:14:47Z] INFO  analytics-service/batch.go:102 report cached and available at /analytics/reports/daily-2024-03-15
[2024-03-15T14:30:00Z] INFO  analytics-service/ingester.go:45 event ingestion rate: 24,500 events/sec (nominal)
[2024-03-15T14:32:00Z] INFO  analytics-service/ingester.go:45 event ingestion rate: 24,800 events/sec (nominal)
[2024-03-15T14:34:00Z] INFO  analytics-service/ingester.go:45 event ingestion rate: 24,200 events/sec (nominal)"""

_ANALYTICS_SERVICE_METRICS = """\
Service: analytics-service
  p50_latency_ms: 18
  p99_latency_ms: 42
  error_rate_5xx: 0.000
  request_rate_rps: 180
  cpu_utilization_pct: 22.0
  memory_utilization_pct: 35.0
  event_ingestion_rate: 24500/sec
  daily_report_status: COMPLETED"""

_USER_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  user-service/handler.go:45 GET /users/usr_28471/profile status=200 latency_ms=42
[2024-03-15T14:33:00Z] INFO  user-service/handler.go:45 GET /users/usr_44192/profile status=200 latency_ms=55
[2024-03-15T14:34:00Z] INFO  user-service/handler.go:45 GET /users/usr_33918/settings status=200 latency_ms=38"""

_NOTIFICATION_SERVICE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  notification-service/sender.go:89 email sent to usr_28471@example.com template=order_confirmation
[2024-03-15T14:33:00Z] WARN  notification-service/sender.go:112 email delivery delayed: SMTP server slow response (1200ms vs 200ms baseline)
[2024-03-15T14:33:01Z] INFO  notification-service/sender.go:89 email sent to usr_44192@example.com template=password_reset
[2024-03-15T14:34:00Z] INFO  notification-service/sender.go:89 email sent to usr_33918@example.com template=order_confirmation"""

_QUEUE_LOGS = """\
[2024-03-15T14:32:00Z] INFO  kafka/broker.go:134 partition rebalance complete for topic=order-events (16 partitions)
[2024-03-15T14:33:00Z] INFO  kafka/broker.go:145 consumer lag: topic=order-events avg_lag=12 max_lag=45 (nominal)
[2024-03-15T14:34:00Z] INFO  kafka/broker.go:145 consumer lag: topic=order-events avg_lag=10 max_lag=38 (nominal)"""

_SYSTEM_OVERVIEW = """\
System Overview -- 2024-03-15T14:35:00Z

  Cluster: prod-us-east-1
  Total Services: 15
  Services Healthy: 11
  Services Degraded: 3 (api-gateway, auth-service, order-service)
  Services Warning: 1 (recommendation-service -- CPU autoscale)
  Services Down: 0

  Active Incidents:
    INC-2024-0315-001: Elevated error rates across multiple services
      Opened: 2024-03-15T14:15:00Z (20 min ago)
      Severity: SEV-2 (auto-classified)
      Affected: ~8% of requests through api-gateway
      On-call: @you

  Recent Activity:
    14:05 - config-service pushed rate-limit updates to 4 services
    14:10 - auth-service canary deployment (v5.1.0-canary)
    14:14 - analytics-service daily report query (852ms)
    14:15 - incident opened (error rate elevation detected)
    14:28 - recommendation-service ML retraining job started
    14:30 - recommendation-service autoscaler triggered
    14:30 - search-service cache warm-up started"""

_SYSTEM_RECENT_CHANGES = """\
Recent Changes (last 24 hours):

  1. [2024-03-15T14:05:04Z] config-service rate-limit config push to 4 services
     Targets: api-gateway, order-service, payment-service, auth-service
     Change: rate limit increases across all targets
     Author: @platform-team
     Status: COMPLETED -- all services acknowledged

  2. [2024-03-15T14:10:00Z] auth-service v5.1.0-canary deployed (10% traffic)
     Change: Refactored OAuth token validation to use claims-validator v3
     Author: ci-bot (PR #2341 by @sarah-auth)
     Status: CANARY_ACTIVE

  3. [2024-03-15T12:15:00Z] cdn DNS configuration update
     Change: Updated CNAME records for static.example.com
     Author: @infra-bot (automated)
     Status: COMPLETED

  4. [2024-03-15T06:00:00Z] database maintenance window
     Change: Routine vacuum and index rebuild (automated)
     Author: dba-automation
     Status: COMPLETED

  5. [2024-03-14T22:00:00Z] notification-service config update
     Change: Adjusted email retry backoff from 30s to 60s
     Author: @alerts-team
     Status: COMPLETED

  6. [2024-03-14T16:00:00Z] queue scaling event
     Change: Increased partition count from 12 to 16 for order-events topic
     Author: @platform-team
     Status: COMPLETED

  7. [2024-03-13T09:00:00Z] search-service v8.2.1 deployed
     Change: Elasticsearch index rebuild, search ranking improvements
     Author: ci-bot (PR #1892 by @search-team)
     Status: STABLE (cache warm-up still in progress)"""

_SYSTEM_DEPENDENCY_GRAPH = """\
Service Dependency Graph:

  api-gateway
    +-- auth-service (authentication for all /api/* routes)
    |     +-- database (session store, revocation lists)
    |     +-- cache (token cache, JWKS key cache)
    +-- user-service
    |     +-- database
    +-- payment-service
    |     +-- database
    |     +-- notification-service
    |           +-- queue
    +-- order-service
    |     +-- auth-service (validates user tokens)
    |     +-- database
    +-- search-service (no auth required for read-only search)
    +-- billing-service
    |     +-- database
    +-- analytics-service
          +-- database

  recommendation-service (standalone, async)
  config-service (pushes configs, no runtime dependency)
  cdn (edge layer, serves static assets only)"""


# ---------------------------------------------------------------------------
# Scenario class
# ---------------------------------------------------------------------------

class HardCanaryScenario(BaseScenario):
    """Intermittent Canary Deployment with Correlated Failures.

    auth-service is running a 90/10 canary deployment of v5.1.0-canary.
    The new version's claims parser rejects provider-B OAuth tokens due to
    a non-standard nested_permissions claim. Only ~10% of traffic hits the
    canary, and only ~10% of users authenticate via provider-B, making the
    effective error rate ~8% -- high enough to be noticeable, low enough to
    be confusing. The errors cascade through order-service and api-gateway.

    Red herrings:
    - recommendation-service has a CPU spike (scheduled ML job).
    - cdn had a DNS config change 2 hours ago (resolved).
    - config-service pushed rate-limit updates 30 min ago.
    - database has a slow 852ms query (scheduled analytics report).
    - payment-service has a TLS certificate renewal warning.
    - search-service has elevated cache miss rate (warm-up after rebuild).
    - billing-service has a CA cert expiry warning (30 days out).

    Intermittent logs: first investigation of auth-service logs shows a
    mostly-clean view with only 2 subtle errors. Second check shows more.
    """

    task_id = "hard_canary"
    name = "Intermittent Canary Deployment Regression"
    difficulty = "hard"
    description = (
        "Elevated error rates across multiple services. Intermittent 500 errors "
        "affecting ~8% of requests. Multiple concurrent alerts. Root cause requires "
        "correlating deployment history, per-pod metrics, provider token formats, "
        "and config changes across multiple investigation steps."
    )

    time_budget = 120
    max_steps = 20

    time_costs = {
        "investigate": 12,
        "diagnose": 8,
        "act": 25,
        "escalate": 5,
    }

    root_cause = (
        "auth-service v5.1.0-canary has OAuth provider-B token validation "
        "bug in new claims parser -- the claims-validator v3 library rejects "
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
        "ANOMALY: Elevated error rates across multiple services. "
        "api-gateway 502 rate at 8%, order-service failures increasing. "
        "recommendation-service CPU alert firing. config-service pushed "
        "updates 20 minutes ago. Possible infrastructure issue. "
        "Started ~25 minutes ago."
    )

    def __init__(self) -> None:
        self.services = self._build_services()
        self.investigation_results = self._build_investigation_results()
        self.red_herrings = self._build_red_herrings()
        self.cascading_effects = self._build_cascading_effects()
        self.relevant_investigations = self._build_relevant_investigations()
        # Track how many times each (target, command) has been investigated
        self._investigation_counts: Dict[Tuple[str, str], int] = {}

    # -- Override get_investigation_result for intermittent logs -------------

    def get_investigation_result(self, target: str, command: str) -> str:
        """Return the text for an ``investigate`` action.

        For auth-service logs specifically, the FIRST investigation returns
        a mostly-clean log view (simulating intermittent errors that are not
        visible in every log window). The SECOND investigation returns a
        log window with more errors visible.

        For all other targets, delegates to the base class behavior.
        """
        key = (target, command)

        # Track investigation count
        count = self._investigation_counts.get(key, 0)
        self._investigation_counts[key] = count + 1

        # Intermittent behavior for auth-service logs
        if key == ("auth-service", "logs"):
            if count == 0:
                return _AUTH_LOGS_FIRST_CHECK
            else:
                return _AUTH_LOGS_SECOND_CHECK

        # All other investigations: use normal lookup
        if key in self.investigation_results:
            return self.investigation_results[key]
        if key in self.red_herrings:
            return self.red_herrings[key]
        return f"No data available for '{command}' on '{target}'."

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
                "Elevated error rates across multiple services. "
                "api-gateway 502 at 8%. order-service failures increasing. "
                "recommendation-service CPU alert. config-service pushed "
                "updates recently. ~25 min ago."
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

        Scoring tiers (stricter than before):
        - 1.0: (rollback or kill_canary) on auth-service AND diagnosis
                contains at least 2 of: "canary", "provider-b", "claims"
        - 0.6: rollback or kill_canary on auth-service (correct action but
                incomplete diagnosis)
        - 0.3: restart auth-service (temporary fix)
        - 0.1: targeted recommendation-service or config-service (red herring)
        - 0.0: no meaningful action or wrong target
        """
        actions_lower = [a.lower() for a in actions_taken]

        # Check if agent did rollback/kill_canary on auth-service
        did_correct_action = False
        for action in actions_lower:
            if ("rollback" in action or "kill_canary" in action) and "auth-service" in action:
                did_correct_action = True
                break

        if did_correct_action:
            # Check diagnosis quality: look for diagnosis actions
            diagnosis_keywords_found = 0
            required_keywords = ["canary", "provider-b", "claims"]
            for action in actions_lower:
                if "diagnose" in action:
                    for kw in required_keywords:
                        if kw in action:
                            diagnosis_keywords_found += 1
            # Also check all actions for keyword presence (agent may
            # include diagnosis info in the action parameters)
            all_actions_text = " ".join(actions_lower)
            keyword_count = sum(1 for kw in required_keywords if kw in all_actions_text)
            diagnosis_keywords_found = max(diagnosis_keywords_found, keyword_count)

            if diagnosis_keywords_found >= 2:
                return 1.0
            else:
                return 0.6

        # Partial: restart auth-service
        for action in actions_lower:
            if "restart" in action and "auth-service" in action:
                return 0.3

        # Red herring: targeted recommendation-service or config-service
        for action in actions_lower:
            if "recommendation-service" in action or "config-service" in action:
                return 0.1

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
                               "order-service", "search-service", "billing-service",
                               "analytics-service"],
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
                latency_ms=95,
                error_rate=0.002,
                cpu_pct=38.0,
                memory_pct=42.0,
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
                latency_ms=12,
                error_rate=0.001,
                cpu_pct=48.0,
                memory_pct=52.3,
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
            "config-service": ServiceInfo(
                name="config-service",
                status="healthy",
                latency_ms=12,
                error_rate=0.0,
                cpu_pct=8.2,
                memory_pct=18.0,
                dependencies=[],
            ),
            "billing-service": ServiceInfo(
                name="billing-service",
                status="healthy",
                latency_ms=28,
                error_rate=0.001,
                cpu_pct=15.0,
                memory_pct=22.0,
                dependencies=["database"],
            ),
            "analytics-service": ServiceInfo(
                name="analytics-service",
                status="healthy",
                latency_ms=18,
                error_rate=0.0,
                cpu_pct=22.0,
                memory_pct=35.0,
                dependencies=["database"],
            ),
        }

    # -- Investigation data -------------------------------------------------

    @staticmethod
    def _build_investigation_results() -> Dict[Tuple[str, str], str]:
        return {
            # auth-service -- logs are handled by get_investigation_result override
            # but we still put second-check here as fallback for base class
            ("auth-service", "logs"): _AUTH_LOGS_SECOND_CHECK,
            ("auth-service", "metrics"): _AUTH_METRICS,
            ("auth-service", "deployments"): _AUTH_DEPLOYMENTS,
            ("auth-service", "dependencies"): _AUTH_DEPENDENCIES,
            ("auth-service", "config"): _AUTH_CONFIG,

            # order-service -- victim / downstream
            ("order-service", "logs"): _ORDER_LOGS,
            ("order-service", "metrics"): _ORDER_METRICS,
            ("order-service", "deployments"): (
                "Deployment History for order-service:\n"
                "  v4.2.1 (current) -- deployed 2024-03-07T10:00:00Z (8 days ago)\n"
                "    Changes: \"Improved order validation error messages\"\n"
                "    Status: STABLE -- no recent changes"
            ),
            ("order-service", "dependencies"): (
                "Service: order-service\n"
                "  Upstream: api-gateway\n"
                "  Downstream:\n"
                "    - auth-service: DEGRADED (intermittent 500s)\n"
                "    - database: HEALTHY"
            ),

            # api-gateway -- victim / entry point
            ("api-gateway", "logs"): _API_GATEWAY_LOGS,
            ("api-gateway", "metrics"): _API_GATEWAY_METRICS,
            ("api-gateway", "deployments"): _API_GATEWAY_DEPLOYMENTS,
            ("api-gateway", "dependencies"): (
                "Service: api-gateway\n"
                "  Upstream: external clients (internet)\n"
                "  Downstream:\n"
                "    - auth-service: DEGRADED\n"
                "    - user-service: HEALTHY\n"
                "    - payment-service: HEALTHY\n"
                "    - order-service: DEGRADED\n"
                "    - search-service: HEALTHY\n"
                "    - billing-service: HEALTHY\n"
                "    - analytics-service: HEALTHY"
            ),

            # user-service -- healthy bystander
            ("user-service", "logs"): _USER_SERVICE_LOGS,
            ("user-service", "metrics"): (
                "Service: user-service\n"
                "  p50_latency_ms: 42\n  p99_latency_ms: 60\n"
                "  error_rate_5xx: 0.003\n  request_rate_rps: 1800\n"
                "  cpu_utilization_pct: 30.0\n  memory_utilization_pct: 35.0"
            ),
            ("user-service", "deployments"): (
                "Deployment History for user-service:\n"
                "  v6.1.0 (current) -- deployed 2024-03-06T14:00:00Z (9 days ago)\n"
                "    Changes: \"Added pagination support for user list endpoint\"\n"
                "    Status: STABLE"
            ),

            # notification-service -- healthy
            ("notification-service", "logs"): _NOTIFICATION_SERVICE_LOGS,
            ("notification-service", "metrics"): (
                "Service: notification-service\n"
                "  p50_latency_ms: 55\n  p99_latency_ms: 100\n"
                "  error_rate_5xx: 0.003\n  request_rate_rps: 420\n"
                "  cpu_utilization_pct: 18.0\n  memory_utilization_pct: 25.0"
            ),

            # database -- healthy but with suspicious slow query
            ("database", "logs"): _DATABASE_LOGS,
            ("database", "metrics"): _DATABASE_METRICS,
            ("database", "deployments"): (
                "Deployment History for database:\n"
                "  PostgreSQL 15.4 -- no application-level deployments\n"
                "  Last maintenance: 2024-03-15T06:00:00Z (routine vacuum)\n"
                "  Status: STABLE"
            ),

            # cache -- healthy
            ("cache", "logs"): _CACHE_LOGS,
            ("cache", "metrics"): _CACHE_METRICS,

            # queue -- healthy
            ("queue", "logs"): _QUEUE_LOGS,
            ("queue", "metrics"): (
                "Service: queue (Kafka 3.6)\n"
                "  latency_ms: 10\n  error_rate: 0.000\n"
                "  consumer_lag_avg: 12\n  consumer_lag_max: 45\n"
                "  partitions: 16\n  cpu_utilization_pct: 8.0\n"
                "  memory_utilization_pct: 15.0"
            ),

            # analytics-service -- healthy
            ("analytics-service", "logs"): _ANALYTICS_SERVICE_LOGS,
            ("analytics-service", "metrics"): _ANALYTICS_SERVICE_METRICS,
            ("analytics-service", "deployments"): (
                "Deployment History for analytics-service:\n"
                "  v2.8.0 (current) -- deployed 2024-03-02T09:00:00Z (13 days ago)\n"
                "    Changes: \"Added daily revenue report aggregation\"\n"
                "    Status: STABLE"
            ),

            # billing-service -- healthy with minor cert warning
            ("billing-service", "logs"): _BILLING_SERVICE_LOGS,
            ("billing-service", "metrics"): _BILLING_SERVICE_METRICS,
            ("billing-service", "deployments"): (
                "Deployment History for billing-service:\n"
                "  v1.12.0 (current) -- deployed 2024-03-09T15:00:00Z (6 days ago)\n"
                "    Changes: \"Invoice template formatting improvements\"\n"
                "    Status: STABLE"
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
            # recommendation-service: CPU spike from ML job
            ("recommendation-service", "logs"): _RECOMMENDATION_LOGS,
            ("recommendation-service", "metrics"): _RECOMMENDATION_METRICS,
            ("recommendation-service", "deployments"): _RECOMMENDATION_DEPLOYMENTS,
            ("recommendation-service", "dependencies"): (
                "Service: recommendation-service\n"
                "  Upstream: api-gateway (async, non-blocking)\n"
                "  Downstream: None (standalone ML service, reads from data-lake)"
            ),
            ("recommendation-service", "config"): (
                "Service: recommendation-service -- Runtime Configuration\n"
                "  model_retraining_schedule: '0 14 * * *' (daily at 14:00 UTC)\n"
                "  autoscaler_enabled: true\n"
                "  autoscaler_min_replicas: 3\n"
                "  autoscaler_max_replicas: 8\n"
                "  autoscaler_target_cpu: 70\n"
                "  current_replicas: 5 (scaled at 14:30Z)"
            ),

            # cdn: DNS change 2 hours ago
            ("cdn", "logs"): _CDN_LOGS,
            ("cdn", "metrics"): (
                "Service: cdn\n"
                "  latency_ms: 25\n  error_rate: 0.001\n"
                "  cache_hit_rate_pct: 98.7\n"
                "  cpu_utilization_pct: 5.0\n  memory_utilization_pct: 10.0\n"
                "  dns_config_change: 2024-03-15T12:15:00Z (2 hours ago)"
            ),
            ("cdn", "deployments"): (
                "Deployment History for cdn:\n"
                "  No application deployments. Infrastructure-managed.\n"
                "  Last config change: DNS CNAME update at 12:15Z."
            ),

            # config-service: pushed rate-limit updates recently
            ("config-service", "logs"): _CONFIG_SERVICE_LOGS,
            ("config-service", "metrics"): _CONFIG_SERVICE_METRICS,
            ("config-service", "deployments"): _CONFIG_SERVICE_DEPLOYMENTS,
            ("config-service", "dependencies"): (
                "Service: config-service\n"
                "  Upstream: none (push-based, triggered by platform team)\n"
                "  Downstream: pushes to api-gateway, order-service, payment-service, auth-service\n"
                "  Last push: 2024-03-15T14:05:04Z (30 min ago)"
            ),
            ("config-service", "config"): (
                "Service: config-service -- Runtime Configuration\n"
                "  push_mode: fire-and-forget with ack\n"
                "  push_timeout_sec: 10\n"
                "  rollback_on_failure: false\n"
                "  audit_log_enabled: true\n"
                "  config_store: etcd (v3.5.9)"
            ),

            # payment-service: cert renewal warning
            ("payment-service", "logs"): _PAYMENT_SERVICE_LOGS,
            ("payment-service", "metrics"): _PAYMENT_SERVICE_METRICS,
            ("payment-service", "deployments"): _PAYMENT_SERVICE_DEPLOYMENTS,
            ("payment-service", "dependencies"): (
                "Service: payment-service\n"
                "  Upstream: api-gateway, order-service\n"
                "  Downstream:\n"
                "    - database: HEALTHY\n"
                "    - notification-service: HEALTHY\n"
                "    - auth-service: DEGRADED (intermittent 500s on pre-check)"
            ),
            ("payment-service", "config"): (
                "Service: payment-service -- Runtime Configuration\n"
                "  tls_cert_path: /etc/ssl/payment-gateway.pem\n"
                "  tls_cert_expiry: 2024-03-29T00:00:00Z (14 days)\n"
                "  mtls_enabled: true\n"
                "  auto_renewal: scheduled 2024-03-22\n"
                "  pci_compliance_mode: strict\n"
                "  auth_pre_check: enabled (validates user token before processing)"
            ),

            # search-service: cache miss rate elevated
            ("search-service", "logs"): _SEARCH_SERVICE_LOGS,
            ("search-service", "metrics"): _SEARCH_SERVICE_METRICS,
            ("search-service", "deployments"): (
                "Deployment History for search-service:\n"
                "  v8.2.1 (current) -- deployed 2024-03-13T09:00:00Z (2 days ago)\n"
                "    Changes: \"Elasticsearch index rebuild, search ranking improvements\"\n"
                "    Status: STABLE (cache warm-up in progress)"
            ),
            ("search-service", "config"): (
                "Service: search-service -- Runtime Configuration\n"
                "  elasticsearch_version: 8.12.0\n"
                "  cache_size: 12M entries\n"
                "  cache_ttl_sec: 3600\n"
                "  cache_warm_up_status: IN_PROGRESS (34% complete)\n"
                "  auth_required: false"
            ),
        }

    # -- Cascading effects --------------------------------------------------

    @staticmethod
    def _build_cascading_effects() -> List[CascadingEffect]:
        return [
            CascadingEffect(
                time_threshold=30,
                service="order-service",
                effect="down",
                description=(
                    "ESCALATION: order-service is now DOWN. Auth failures have "
                    "exhausted the retry budget and circuit breaker has tripped. "
                    "All order creation is failing."
                ),
            ),
            CascadingEffect(
                time_threshold=60,
                service="api-gateway",
                effect="degraded",
                description=(
                    "ESCALATION: api-gateway error rate has spiked to 20%. "
                    "Cascading auth failures are now affecting all authenticated "
                    "endpoints. Load balancer health checks are flagging instances."
                ),
            ),
            CascadingEffect(
                time_threshold=80,
                service="payment-service",
                effect="degraded",
                description=(
                    "ESCALATION: payment-service is now DEGRADED. Auth pre-check "
                    "failures are causing payment authorization to fail. Revenue "
                    "impact detected. Finance team auto-paged."
                ),
            ),
            CascadingEffect(
                time_threshold=100,
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
