"""Medium scenario: Cascading Database Connection Pool Exhaustion.

A user-service bulk sync deployment (v3.2.0) contains a connection leak that
gradually exhausts the shared PostgreSQL connection pool.  Symptoms first
appear in payment-service and order-service (timeouts acquiring connections),
but the root cause is user-service holding ~94 connections that are never
released.

Difficulty: MEDIUM -- the agent must trace from downstream symptoms
(payment-service pool exhaustion errors) back through the shared database
connection pool to user-service as the leaking culprit, then either restart
or rollback user-service.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple
from uuid import uuid4

from incident_env.models import IncidentObservation, IncidentState
from incident_env.scenarios.base import BaseScenario, CascadingEffect, ServiceInfo


# ---------------------------------------------------------------------------
# Log blocks -- kept as module-level constants for readability
# ---------------------------------------------------------------------------

_PAYMENT_SERVICE_LOGS = """\
[2024-03-15T13:45:22Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=48, idle=0, max=50)
[2024-03-15T13:45:21Z] ERROR payment-service/handler.go:112 PaymentProcessor.ChargeCard: context deadline exceeded after 8012ms
[2024-03-15T13:45:20Z] WARN  payment-service/handler.go:89 Transaction timeout after 5000ms for order #ORD-28471
[2024-03-15T13:44:58Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=50, idle=0, max=50)
[2024-03-15T13:44:55Z] WARN  payment-service/circuit.go:67 Circuit breaker OPEN for db-write after 12 consecutive failures
[2024-03-15T13:44:31Z] WARN  payment-service/handler.go:201 Retrying payment processing for txn TXN-9982, attempt 3/3
[2024-03-15T13:44:30Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=49, idle=0, max=50)
[2024-03-15T13:43:45Z] WARN  payment-service/handler.go:201 Retrying payment processing for txn TXN-9982, attempt 2/3
[2024-03-15T13:43:12Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=50, idle=0, max=50)
[2024-03-15T13:42:45Z] INFO  payment-service/health.go:34 Health check: DB pool utilization 96% (48/50), response time degraded
[2024-03-15T13:42:01Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=50, idle=0, max=50)
[2024-03-15T13:41:33Z] WARN  payment-service/handler.go:89 Transaction timeout after 5000ms for order #ORD-28464
[2024-03-15T13:40:12Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted (active=49, idle=0, max=50)
[2024-03-15T13:39:50Z] INFO  payment-service/health.go:34 Health check: DB pool utilization 92% (46/50), response time degraded
[2024-03-15T13:38:22Z] WARN  payment-service/circuit.go:55 Circuit breaker HALF-OPEN for db-write, testing 1 request
[2024-03-15T13:37:15Z] ERROR payment-service/db.go:156 Failed to acquire DB connection: pool exhausted"""

_PAYMENT_SERVICE_METRICS = """\
=== payment-service Metrics (last 60 minutes) ===

  p50_latency_ms:     3200    (baseline: 120)
  p99_latency_ms:    12400    (baseline: 450)
  requests_per_sec:    340    (baseline: 820)
  error_rate_5xx:      0.60   (baseline: 0.002)
  active_db_conns:       50   (max: 50)  *** POOL SATURATED ***
  idle_db_conns:          0   (baseline: 35)
  conn_wait_queue:       28   (threads waiting for a connection)
  conn_acquire_p99_ms: 5200   (baseline: 2)
  cpu_utilization_pct:   40
  memory_utilization_pct: 50
  gc_pause_ms_avg:       12   (normal)
  thread_count:         180   (baseline: 120, elevated due to blocked threads)

  Connection pool timeline (5-min buckets):
    13:00  active=22  idle=28  wait=0
    13:05  active=29  idle=21  wait=0
    13:10  active=35  idle=15  wait=0
    13:15  active=42  idle=8   wait=2
    13:20  active=47  idle=3   wait=8
    13:25  active=49  idle=1   wait=14
    13:30  active=50  idle=0   wait=19
    13:35  active=50  idle=0   wait=22
    13:40  active=50  idle=0   wait=25
    13:45  active=50  idle=0   wait=28"""

_PAYMENT_SERVICE_DEPLOYMENTS = """\
Deployment History for payment-service:
  v4.1.1 - deployed 2024-03-14T16:30:00Z (yesterday)
    Changes: "Update payment form CSS for mobile responsiveness"
    Commit: abc789f - "fix: align payment button on narrow viewports"
    PR: #2103 - "Mobile payment form styling fixes"
    Image: payment-service:v4.1.1
    Status: RUNNING
    Note: CSS-only change, no backend logic modified

  v4.1.0 - deployed 2024-03-11T10:15:00Z (4 days ago)
    Changes: "Add Apple Pay integration"
    Commit: 77e2a1b - "feat: apple pay tokenization flow"
    Status: STABLE (ran 3 days without issues before v4.1.1)"""

_USER_SERVICE_LOGS = """\
[2024-03-15T13:45:30Z] WARN  user-service/sync.go:345 Sync job still running after 47 minutes, connections held: 94
[2024-03-15T13:42:18Z] WARN  user-service/sync.go:345 Sync job still running after 44 minutes, connections held: 94
[2024-03-15T13:40:01Z] DEBUG user-service/sync.go:289 Processing batch 487/500, acquired connection #94
[2024-03-15T13:38:22Z] DEBUG user-service/sync.go:289 Processing batch 479/500, acquired connection #94
[2024-03-15T13:35:44Z] ERROR user-service/db_pool.go:45 Connection pool nearing global limit: active=142, max=150 (shared pool)
[2024-03-15T13:32:11Z] DEBUG user-service/sync.go:289 Processing batch 451/500, acquired connection #93
[2024-03-15T13:28:55Z] WARN  user-service/sync.go:312 Batch processing slower than expected, maintaining 8 parallel workers
[2024-03-15T13:25:33Z] DEBUG user-service/sync.go:289 Processing batch 412/500, acquired connection #91
[2024-03-15T13:20:01Z] WARN  user-service/sync.go:345 Sync job still running after 22 minutes, connections held: 89
[2024-03-15T13:15:44Z] ERROR user-service/db_pool.go:45 Connection pool nearing limit: active=128, max=150 (shared pool)
[2024-03-15T13:12:30Z] DEBUG user-service/sync.go:289 Processing batch 310/500, acquired connection #78
[2024-03-15T13:10:05Z] WARN  user-service/sync.go:312 Batch processing slow, increasing parallelism to 8 workers
[2024-03-15T13:05:33Z] DEBUG user-service/sync.go:289 Processing batch 127/500, acquired connection #45
[2024-03-15T13:02:15Z] WARN  user-service/sync.go:312 Batch processing slow, increasing parallelism to 4 workers
[2024-03-15T12:58:03Z] DEBUG user-service/sync.go:289 Processing batch 2/500, acquired connection #2
[2024-03-15T12:58:02Z] DEBUG user-service/sync.go:267 Opening DB connection for user batch processing...
[2024-03-15T12:58:01Z] INFO  user-service/sync.go:234 Starting bulk user profile sync job (batch_id: SYNC-4521)
[2024-03-15T12:57:59Z] INFO  user-service/main.go:102 Sync scheduler triggered: running new BulkProfileSync task"""

_USER_SERVICE_METRICS = """\
=== user-service Metrics (last 60 minutes) ===

  p50_latency_ms:     4200    (baseline: 85)
  p99_latency_ms:     8500    (baseline: 320)
  requests_per_sec:    190    (baseline: 650)
  error_rate_5xx:      0.45   (baseline: 0.003)
  active_db_conns:       94   *** LEAKING - NEVER RETURNED TO POOL ***
  idle_db_conns:          0   (baseline: 20)
  conn_acquire_p99_ms: 8200   (baseline: 3)
  cpu_utilization_pct:   65
  memory_utilization_pct: 70
  gc_pause_ms_avg:       45   (elevated, large object graph from sync)
  goroutine_count:      412   (baseline: 80, elevated due to sync workers)

  Connection count over time (user-service held connections):
    12:55  held=0
    12:58  held=2    <-- sync job started
    13:00  held=12
    13:05  held=45
    13:10  held=62
    13:15  held=78
    13:20  held=89
    13:25  held=91
    13:30  held=93
    13:35  held=94
    13:40  held=94   <-- plateau, pool nearly full
    13:45  held=94

  NOTE: connections acquired by sync.go are never released back to the pool.
  defer conn.Close() is missing in the batch processing loop."""

_USER_SERVICE_DEPLOYMENTS = """\
Deployment History for user-service:
  v3.2.0 - deployed 2024-03-15T12:55:00Z (50 minutes ago) by ci-bot
    Changes: "Add bulk user profile sync with parallel processing"
    Commit: def456a - "implement parallel batch sync for user profiles"
    PR: #1847 - "Bulk sync to reduce profile staleness"
    Image: user-service:v3.2.0
    Status: RUNNING
    Note: New feature - first production deployment
    Rollback target: v3.1.2

  v3.1.2 - deployed 2024-03-13T09:00:00Z (2 days ago)
    Changes: "Fix email validation regex for edge cases"
    Commit: 8a1bc3e - "fix: handle plus-sign in email local part"
    Status: STABLE (ran 2 days without issues)

  v3.1.1 - deployed 2024-03-10T14:20:00Z (5 days ago)
    Changes: "Improve user search query performance"
    Status: STABLE"""

_USER_SERVICE_DEPENDENCIES = """\
Dependencies for user-service:
  -> database (PostgreSQL 15.4)
     Connection pool: SHARED pool (150 max connections across all services)
     Current usage by user-service: 94 connections (62.7% of shared pool)
     Status: connections acquired but NOT being returned

  -> cache (Redis 7.2)
     Connection pool: dedicated (max 20)
     Current usage: 8 connections
     Status: healthy, cache hit rate 94.2%"""

_USER_SERVICE_CONFIG = """\
Configuration for user-service (v3.2.0):
  db_pool_max_connections: 100  (per-service soft limit)
  db_pool_min_idle: 5
  db_connection_timeout_ms: 5000
  bulk_sync_enabled: true        <-- NEW in v3.2.0
  bulk_sync_batch_size: 500
  bulk_sync_parallelism: 2       (auto-scaled to 8 under load)
  bulk_sync_connection_reuse: false  <-- BUG: should be true
  profile_cache_ttl_sec: 3600
  request_timeout_ms: 10000"""

_DATABASE_LOGS = """\
[2024-03-15T13:45:00Z] WARN  postgres [pid=1204]: connection pool utilization at 94.7% (142/150 connections active)
[2024-03-15T13:44:30Z] LOG   postgres [pid=1204]: active connections by source:
                         user-service:     94 (pids 28401-28494)
                         payment-service:  26 (pids 29101-29126)
                         auth-service:     12 (pids 30001-30012)
                         order-service:     8 (pids 30201-30208)
                         api-gateway:       2 (pids 31001-31002)
[2024-03-15T13:40:00Z] LOG   postgres [pid=1204]: longest running transaction: user_service.sync_profiles (running for 2847s, pid 28401)
[2024-03-15T13:35:00Z] WARN  postgres [pid=1204]: 89 connections held by user-service (pid range 28401-28489), none returned in last 37 minutes
[2024-03-15T13:30:00Z] LOG   postgres [pid=1204]: connection pool utilization at 78.0% (117/150 connections active)
[2024-03-15T13:25:00Z] LOG   postgres [pid=1204]: connection pool utilization at 65.3% (98/150 connections active)
[2024-03-15T13:20:00Z] LOG   postgres [pid=1204]: connection pool utilization at 52.0% (78/150 connections active)
[2024-03-15T13:15:00Z] LOG   postgres [pid=1204]: connection pool utilization at 40.7% (61/150 connections active)
[2024-03-15T13:10:00Z] LOG   postgres [pid=1204]: connection pool utilization at 30.0% (45/150 connections active)
[2024-03-15T13:05:00Z] LOG   postgres [pid=1204]: connection pool utilization at 18.7% (28/150 connections active)
[2024-03-15T13:00:00Z] LOG   postgres [pid=1204]: checkpoint complete: wrote 1247 buffers (7.6%); 0 WAL file(s) added
[2024-03-15T12:58:05Z] LOG   postgres [pid=1204]: new connections burst detected from user-service (12 connections in 3 seconds)
[2024-03-15T12:55:00Z] LOG   postgres [pid=1204]: connection pool utilization at 12.0% (18/150 connections active)"""

_DATABASE_METRICS = """\
=== database (PostgreSQL 15.4) Metrics (last 60 minutes) ===

  active_connections:    142    (max: 150)  *** NEAR CAPACITY ***
  idle_connections:        8
  waiting_connections:    34    (clients blocked waiting for a connection)
  connections_by_service:
    user-service:         94   (62.7%)  *** DOMINANT CONSUMER ***
    payment-service:      26   (17.3%)
    auth-service:         12   (8.0%)
    order-service:         8   (5.3%)
    api-gateway:           2   (1.3%)
  longest_txn_seconds:  2847   (user_service.sync_profiles, pid 28401)
  lock_waits_per_sec:     12   (baseline: 0.3)
  deadlocks_total:         0
  query_latency_p50_ms:   18   (baseline: 5)
  query_latency_p99_ms:  280   (baseline: 45)
  rows_fetched_per_sec: 42000  (elevated due to bulk sync)
  cpu_utilization_pct:    75
  memory_utilization_pct: 60
  disk_iops:             850   (baseline: 200)
  replication_lag_ms:      3   (healthy)

  Pool utilization timeline (5-min buckets):
    12:55  active=18   idle=132  waiting=0
    13:00  active=28   idle=122  waiting=0
    13:05  active=45   idle=105  waiting=0
    13:10  active=61   idle=89   waiting=0
    13:15  active=78   idle=72   waiting=0
    13:20  active=98   idle=52   waiting=2
    13:25  active=117  idle=33   waiting=8
    13:30  active=128  idle=22   waiting=15
    13:35  active=136  idle=14   waiting=22
    13:40  active=140  idle=10   waiting=28
    13:45  active=142  idle=8    waiting=34"""

_DATABASE_DEPLOYMENTS = """\
Deployment History for database:
  PostgreSQL 15.4 - no recent changes
  Last configuration change: 2024-03-01 (increased max_connections from 100 to 150)
  Last failover: 2024-02-20 (planned maintenance)
  Replication: streaming, 1 replica, lag < 5ms"""

_DATABASE_DEPENDENCIES = """\
Dependencies for database:
  <- upstream consumers (services connecting to this database):
     - user-service (94 active connections)
     - payment-service (26 active connections)
     - auth-service (12 active connections)
     - order-service (8 active connections)
     - api-gateway (2 active connections)

  -> downstream:
     - replica-database (streaming replication, healthy, lag 3ms)
     - pgbouncer: NOT in use (direct connections)"""

_AUTH_SERVICE_LOGS = """\
[2024-03-15T13:45:10Z] ERROR auth-service/auth.go:78 Token validation failed: DB query timeout after 5000ms
[2024-03-15T13:44:52Z] WARN  auth-service/pool.go:34 Connection acquire timeout: waited 4200ms for DB connection
[2024-03-15T13:44:33Z] ERROR auth-service/auth.go:78 Token validation failed: DB query timeout after 5000ms
[2024-03-15T13:43:58Z] WARN  auth-service/pool.go:34 Connection acquire timeout: waited 3800ms for DB connection
[2024-03-15T13:42:11Z] ERROR auth-service/auth.go:112 Failed to refresh session: connection pool exhausted
[2024-03-15T13:40:45Z] WARN  auth-service/pool.go:34 Connection acquire timeout: waited 2900ms for DB connection
[2024-03-15T13:38:22Z] WARN  auth-service/auth.go:95 Elevated auth latency: p99=4800ms (SLA target: 200ms)
[2024-03-15T13:35:00Z] INFO  auth-service/health.go:22 Health check: DB connection acquire time elevated (p99: 3200ms)
[2024-03-15T13:30:00Z] INFO  auth-service/health.go:22 Health check: DB connection acquire time elevated (p99: 1800ms)
[2024-03-15T13:25:00Z] INFO  auth-service/health.go:22 Health check: nominal"""

_AUTH_SERVICE_METRICS = """\
=== auth-service Metrics (last 60 minutes) ===

  p50_latency_ms:     2100    (baseline: 35)
  p99_latency_ms:     4800    (baseline: 150)
  requests_per_sec:    520    (baseline: 1200)
  error_rate_5xx:      0.25   (baseline: 0.001)
  active_db_conns:       12   (max: 20)
  idle_db_conns:          0   (baseline: 12)
  conn_acquire_p99_ms: 4200   (baseline: 1)
  token_validations/sec: 480  (baseline: 1100)
  cache_hit_rate:      0.72   (baseline: 0.95, degraded because DB-backed sessions timing out)
  cpu_utilization_pct:   30
  memory_utilization_pct: 40"""

_ORDER_SERVICE_LOGS = """\
[2024-03-15T13:45:18Z] ERROR order-service/db.go:89 Failed to acquire DB connection: pool exhausted (active=8, idle=0, max=10)
[2024-03-15T13:44:55Z] WARN  order-service/handler.go:156 Order creation timeout for customer C-88231, attempt 2/3
[2024-03-15T13:44:12Z] ERROR order-service/handler.go:201 Order #ORD-28473 failed: payment-service returned 503
[2024-03-15T13:43:30Z] WARN  order-service/handler.go:156 Order creation timeout for customer C-87994
[2024-03-15T13:42:05Z] ERROR order-service/db.go:89 Failed to acquire DB connection: waited 6200ms, max wait 5000ms
[2024-03-15T13:40:33Z] WARN  order-service/handler.go:67 Downstream payment-service returning errors (5/5 recent calls failed)
[2024-03-15T13:38:00Z] INFO  order-service/health.go:19 Health check: degraded - DB connections scarce, payment-service unhealthy
[2024-03-15T13:35:00Z] INFO  order-service/health.go:19 Health check: nominal"""

_ORDER_SERVICE_METRICS = """\
=== order-service Metrics (last 60 minutes) ===

  p50_latency_ms:     2800    (baseline: 95)
  p99_latency_ms:     6000    (baseline: 380)
  requests_per_sec:    180    (baseline: 450)
  error_rate_5xx:      0.30   (baseline: 0.002)
  active_db_conns:        8   (max: 10)
  idle_db_conns:          0   (baseline: 6)
  conn_acquire_p99_ms: 6200   (baseline: 2)
  orders_created/sec:    45   (baseline: 200)
  orders_failed/sec:     55   (baseline: 1)
  cpu_utilization_pct:   35
  memory_utilization_pct: 45"""

_API_GATEWAY_LOGS = """\
[2024-03-15T13:45:25Z] ERROR api-gateway/proxy.go:234 Upstream auth-service returned 503 for request REQ-8827461
[2024-03-15T13:45:22Z] WARN  api-gateway/proxy.go:189 Request REQ-8827459 exceeded timeout (5200ms): upstream payment-service
[2024-03-15T13:45:15Z] ERROR api-gateway/proxy.go:234 Upstream user-service returned 503 for request REQ-8827455
[2024-03-15T13:44:58Z] WARN  api-gateway/proxy.go:189 Request REQ-8827448 exceeded timeout (5100ms): upstream order-service
[2024-03-15T13:44:30Z] ERROR api-gateway/proxy.go:234 Upstream payment-service returned 503 for request REQ-8827431
[2024-03-15T13:43:50Z] WARN  api-gateway/retry.go:45 Retry budget exhausted for payment-service (5/5 retries failed)
[2024-03-15T13:42:15Z] WARN  api-gateway/proxy.go:189 Request REQ-8827390 exceeded timeout: upstream auth-service
[2024-03-15T13:40:00Z] INFO  api-gateway/health.go:28 Health check: degraded - 3/4 upstream services unhealthy
[2024-03-15T13:35:00Z] INFO  api-gateway/health.go:28 Health check: degraded - 1/4 upstream services slow
[2024-03-15T13:30:00Z] INFO  api-gateway/health.go:28 Health check: nominal"""

_API_GATEWAY_METRICS = """\
=== api-gateway Metrics (last 60 minutes) ===

  p50_latency_ms:     2400    (baseline: 65)
  p99_latency_ms:     5200    (baseline: 250)
  requests_per_sec:    890    (baseline: 2400)
  error_rate_5xx:      0.35   (baseline: 0.003)
  active_upstream_conns: 240  (baseline: 180)
  upstream_timeout_rate: 0.32 (baseline: 0.001)
  retry_rate:           0.45  (baseline: 0.01)
  cpu_utilization_pct:   55   (elevated due to retries)
  memory_utilization_pct: 45
  request_queue_depth:   120  (baseline: 5)

  Upstream error breakdown:
    payment-service:  60% of errors
    user-service:     22% of errors
    auth-service:     15% of errors
    order-service:     3% of errors"""

_NOTIFICATION_SERVICE_LOGS = """\
[2024-03-15T13:45:00Z] INFO  notification-service/worker.go:45 Processed 342 notifications in last 5 minutes
[2024-03-15T13:40:00Z] INFO  notification-service/worker.go:45 Processed 358 notifications in last 5 minutes
[2024-03-15T13:35:00Z] INFO  notification-service/worker.go:45 Processed 361 notifications in last 5 minutes
[2024-03-15T13:30:00Z] INFO  notification-service/health.go:18 Health check: nominal
[2024-03-15T13:25:00Z] INFO  notification-service/health.go:18 Health check: nominal"""

_CACHE_LOGS = """\
[2024-03-15T13:45:00Z] INFO  redis: 0 clients connected (max: 1000), memory used: 256MB/1024MB
[2024-03-15T13:40:00Z] INFO  redis: keyspace: db0=124521 keys, expires=89201
[2024-03-15T13:35:00Z] INFO  redis: hit rate 97.2%, evictions 0, connected clients 42
[2024-03-15T13:30:00Z] INFO  redis: health check: nominal"""

_QUEUE_LOGS = """\
[2024-03-15T13:45:00Z] INFO  rabbitmq: queues healthy, 12 consumers, 0 messages unacked
[2024-03-15T13:40:00Z] INFO  rabbitmq: notifications queue: 0 pending, 342 delivered/5min
[2024-03-15T13:35:00Z] INFO  rabbitmq: all queues nominal"""

_SYSTEM_OVERVIEW = """\
=== System Overview ===

Cluster: prod-us-east-1
Total services: 9 (4 degraded/critical, 5 healthy)
Shared resource: PostgreSQL connection pool (150 max)
  Current utilization: 142/150 (94.7%) *** CRITICAL ***

Service Health Summary:
  api-gateway:           DEGRADED  (latency 5200ms, errors 35%)
  auth-service:          DEGRADED  (latency 4800ms, errors 25%)
  user-service:          CRITICAL  (latency 8500ms, errors 45%)
  payment-service:       CRITICAL  (latency 12000ms, errors 60%)
  order-service:         DEGRADED  (latency 6000ms, errors 30%)
  notification-service:  HEALTHY   (latency 100ms)
  database:              DEGRADED  (pool 94.7% full, query latency elevated)
  cache:                 HEALTHY   (latency 3ms)
  queue:                 HEALTHY   (latency 15ms)

Impact: Payment processing down, order creation failing, user authentication intermittent.
Customer-facing error rate: 35% of all API requests returning 5xx.
Revenue impact estimate: ~$12,400/hour in lost transactions.

Timeline:
  12:55  user-service v3.2.0 deployed
  12:58  user-service bulk sync job started
  13:10  database connection pool utilization crosses 30%
  13:20  first connection acquire timeouts in payment-service
  13:25  payment-service circuit breaker trips
  13:30  order-service starts failing
  13:35  auth-service latency exceeds SLA
  13:45  current state - 4 services degraded/critical"""

_SYSTEM_RECENT_CHANGES = """\
=== Recent Changes (last 48 hours) ===

  2024-03-15T12:55:00Z  user-service v3.2.0 deployed
    Author: ci-bot (PR #1847)
    Change: "Add bulk user profile sync with parallel processing"
    Impact: NEW FEATURE - first production run
    *** CORRELATES WITH INCIDENT START ***

  2024-03-14T16:30:00Z  payment-service v4.1.1 deployed
    Author: frontend-team
    Change: "Update payment form CSS for mobile responsiveness"
    Impact: CSS-only, no backend changes

  2024-03-14T09:00:00Z  DNS TTL change (infra)
    Change: Reduced TTL from 300s to 60s for faster failover
    Impact: Brief resolution blip during propagation (resolved)

  2024-03-13T09:00:00Z  user-service v3.1.2 deployed
    Author: backend-team
    Change: "Fix email validation regex"
    Impact: Patch, stable for 2 days"""

_SYSTEM_DEPENDENCY_GRAPH = """\
=== Service Dependency Graph ===

  api-gateway
    -> auth-service (authentication)
    -> user-service (user data)
    -> payment-service (payments)
    -> order-service (orders)

  auth-service
    -> database (session/token storage)

  user-service
    -> database (user profiles)  *** HOLDING 94 CONNECTIONS ***
    -> cache (profile cache)

  payment-service
    -> database (transaction records)
    -> notification-service (payment confirmations)

  order-service
    -> database (order storage)
    -> payment-service (payment processing)

  notification-service
    -> queue (async delivery)

  database
    <- auth-service, user-service, payment-service, order-service, api-gateway
    Connection pool: SHARED, 150 max
    Current: 142 active, 8 idle, 34 waiting

  cache (Redis)
    <- user-service

  queue (RabbitMQ)
    <- notification-service"""


# ---------------------------------------------------------------------------
# Scenario class
# ---------------------------------------------------------------------------

class MediumDBPoolScenario(BaseScenario):
    """Cascading Database Connection Pool Exhaustion.

    Root cause: ``user-service`` v3.2.0 introduced a bulk profile sync job
    that opens a new database connection per batch but never releases them
    (``defer conn.Close()`` is missing).  Over ~45 minutes the sync job
    acquires 94 of the shared PostgreSQL pool's 150 connections, starving
    payment-service, order-service, and auth-service.

    The agent must trace from the visible symptoms (payment-service errors,
    api-gateway latency) back through the shared database pool to
    user-service as the leaking consumer.
    """

    # -- Identity -----------------------------------------------------------
    task_id: str = "medium_db_pool"
    name: str = "Cascading Database Connection Pool Exhaustion"
    difficulty: str = "medium"
    description: str = (
        "Multiple services are experiencing high latency and connection "
        "timeouts.  A shared PostgreSQL connection pool is nearly exhausted.  "
        "Trace the symptoms to their source and remediate."
    )

    # -- Alert --------------------------------------------------------------
    initial_alert: str = (
        "WARNING: Multiple services reporting high latency. "
        "payment-service P99 > 5s. order-service and auth-service also degraded. "
        "Started 45 minutes ago, gradually worsening."
    )

    # -- Timing -------------------------------------------------------------
    time_budget: int = 240
    max_steps: int = 25

    def __init__(self) -> None:
        # -- Services -------------------------------------------------------
        self.services: Dict[str, ServiceInfo] = {
            "api-gateway": ServiceInfo(
                name="api-gateway",
                status="degraded",
                latency_ms=5200,
                error_rate=0.35,
                cpu_pct=55.0,
                memory_pct=45.0,
                dependencies=["auth-service", "user-service", "payment-service", "order-service"],
            ),
            "auth-service": ServiceInfo(
                name="auth-service",
                status="degraded",
                latency_ms=4800,
                error_rate=0.25,
                cpu_pct=30.0,
                memory_pct=40.0,
                dependencies=["database"],
            ),
            "user-service": ServiceInfo(
                name="user-service",
                status="critical",
                latency_ms=8500,
                error_rate=0.45,
                cpu_pct=65.0,
                memory_pct=70.0,
                dependencies=["database", "cache"],
            ),
            "payment-service": ServiceInfo(
                name="payment-service",
                status="critical",
                latency_ms=12000,
                error_rate=0.60,
                cpu_pct=40.0,
                memory_pct=50.0,
                dependencies=["database", "notification-service"],
            ),
            "order-service": ServiceInfo(
                name="order-service",
                status="degraded",
                latency_ms=6000,
                error_rate=0.30,
                cpu_pct=35.0,
                memory_pct=45.0,
                dependencies=["database", "payment-service"],
            ),
            "notification-service": ServiceInfo(
                name="notification-service",
                status="healthy",
                latency_ms=100,
                error_rate=0.005,
                cpu_pct=20.0,
                memory_pct=30.0,
                dependencies=["queue"],
            ),
            "database": ServiceInfo(
                name="database",
                status="degraded",
                latency_ms=2500,
                error_rate=0.15,
                cpu_pct=75.0,
                memory_pct=60.0,
                dependencies=[],
            ),
            "cache": ServiceInfo(
                name="cache",
                status="healthy",
                latency_ms=3,
                error_rate=0.001,
                cpu_pct=10.0,
                memory_pct=25.0,
                dependencies=[],
            ),
            "queue": ServiceInfo(
                name="queue",
                status="healthy",
                latency_ms=15,
                error_rate=0.0,
                cpu_pct=12.0,
                memory_pct=20.0,
                dependencies=[],
            ),
        }

        # -- Investigation results ------------------------------------------
        self.investigation_results: Dict[Tuple[str, str], str] = {
            # payment-service
            ("payment-service", "logs"): _PAYMENT_SERVICE_LOGS,
            ("payment-service", "metrics"): _PAYMENT_SERVICE_METRICS,
            ("payment-service", "deployments"): _PAYMENT_SERVICE_DEPLOYMENTS,
            # user-service (ROOT CAUSE)
            ("user-service", "logs"): _USER_SERVICE_LOGS,
            ("user-service", "metrics"): _USER_SERVICE_METRICS,
            ("user-service", "deployments"): _USER_SERVICE_DEPLOYMENTS,
            ("user-service", "dependencies"): _USER_SERVICE_DEPENDENCIES,
            ("user-service", "config"): _USER_SERVICE_CONFIG,
            # database
            ("database", "logs"): _DATABASE_LOGS,
            ("database", "metrics"): _DATABASE_METRICS,
            ("database", "deployments"): _DATABASE_DEPLOYMENTS,
            ("database", "dependencies"): _DATABASE_DEPENDENCIES,
            # auth-service
            ("auth-service", "logs"): _AUTH_SERVICE_LOGS,
            ("auth-service", "metrics"): _AUTH_SERVICE_METRICS,
            # order-service
            ("order-service", "logs"): _ORDER_SERVICE_LOGS,
            ("order-service", "metrics"): _ORDER_SERVICE_METRICS,
            # api-gateway
            ("api-gateway", "logs"): _API_GATEWAY_LOGS,
            ("api-gateway", "metrics"): _API_GATEWAY_METRICS,
            # notification-service
            ("notification-service", "logs"): _NOTIFICATION_SERVICE_LOGS,
            # cache
            ("cache", "logs"): _CACHE_LOGS,
            # queue
            ("queue", "logs"): _QUEUE_LOGS,
            # system-level
            ("system", "overview"): _SYSTEM_OVERVIEW,
            ("system", "recent_changes"): _SYSTEM_RECENT_CHANGES,
            ("system", "dependency_graph"): _SYSTEM_DEPENDENCY_GRAPH,
        }

        # -- Red herrings ---------------------------------------------------
        self.red_herrings: Dict[Tuple[str, str], str] = {
            ("api-gateway", "deployments"): (
                "Deployment History for api-gateway:\n"
                "  No deployments in the last 7 days.\n"
                "  Last deploy: v2.8.3 on 2024-03-08 (routine dependency bump)"
            ),
            ("api-gateway", "config"): (
                "Configuration for api-gateway:\n"
                "  upstream_timeout_ms: 5000\n"
                "  max_retries: 3\n"
                "  retry_backoff_ms: 500\n"
                "  circuit_breaker_threshold: 5\n"
                "  rate_limit_rps: 5000\n"
                "  NOTE: No recent config changes."
            ),
            ("payment-service", "dependencies"): (
                "Dependencies for payment-service:\n"
                "  -> database (transaction records, pool: shared)\n"
                "  -> notification-service (payment confirmations via queue)\n"
                "  -> external: stripe-api (payment gateway, healthy, latency 120ms)\n"
                "  All external dependencies healthy."
            ),
            ("payment-service", "config"): (
                "Configuration for payment-service:\n"
                "  db_pool_max_connections: 50\n"
                "  transaction_timeout_ms: 5000\n"
                "  retry_max_attempts: 3\n"
                "  stripe_api_timeout_ms: 3000\n"
                "  NOTE: No recent config changes."
            ),
            ("auth-service", "deployments"): (
                "Deployment History for auth-service:\n"
                "  No deployments in the last 7 days.\n"
                "  Last deploy: v2.4.0 on 2024-03-06 (added OAuth2 PKCE support)\n"
                "  Status: STABLE"
            ),
            ("auth-service", "config"): (
                "Configuration for auth-service:\n"
                "  db_pool_max_connections: 20\n"
                "  token_ttl_sec: 3600\n"
                "  session_cache_enabled: true\n"
                "  bcrypt_rounds: 12\n"
                "  NOTE: No recent config changes."
            ),
            ("order-service", "deployments"): (
                "Deployment History for order-service:\n"
                "  No deployments in the last 7 days.\n"
                "  Last deploy: v5.0.1 on 2024-03-07\n"
                "  Status: STABLE"
            ),
            ("notification-service", "metrics"): (
                "=== notification-service Metrics ===\n"
                "  p50_latency_ms:     80    (baseline: 75)\n"
                "  p99_latency_ms:    100    (baseline: 95)\n"
                "  notifications/sec:  68    (baseline: 72)\n"
                "  error_rate:       0.005   (baseline: 0.003)\n"
                "  cpu_utilization:    20%\n"
                "  memory_utilization: 30%\n"
                "  Status: HEALTHY"
            ),
            ("cache", "metrics"): (
                "=== cache (Redis 7.2) Metrics ===\n"
                "  connected_clients:   42\n"
                "  hit_rate:          97.2%\n"
                "  evictions:            0\n"
                "  memory_used:      256MB / 1024MB\n"
                "  ops_per_sec:       4200\n"
                "  latency_p99_ms:       3\n"
                "  Status: HEALTHY"
            ),
            ("queue", "metrics"): (
                "=== queue (RabbitMQ) Metrics ===\n"
                "  consumers:           12\n"
                "  messages_ready:       0\n"
                "  messages_unacked:     0\n"
                "  deliver_rate:      68/s\n"
                "  publish_rate:      70/s\n"
                "  Status: HEALTHY"
            ),
            ("network", "metrics"): (
                "=== Network Metrics ===\n"
                "  DNS resolution latency: 2ms (normal)\n"
                "  NOTE: Brief DNS resolution blip at 10:15 UTC today (3 hours ago),\n"
                "  lasted 45 seconds, fully resolved. Unrelated to current incident.\n"
                "  Inter-service packet loss: 0.00%\n"
                "  Load balancer health: all backends registered"
            ),
        }

        # -- Ground truth ---------------------------------------------------
        self.root_cause: str = (
            "user-service v3.2.0 connection leak in bulk sync job exhausting "
            "shared database connection pool"
        )
        self.root_cause_keywords: Set[str] = {
            "user-service",
            "connection leak",
            "connection pool",
            "db pool",
            "pool exhaustion",
            "bulk sync",
        }
        self.optimal_actions: List[str] = [
            "restart user-service",
            "rollback user-service",
        ]

        # -- Relevant investigations ----------------------------------------
        self.relevant_investigations: Set[Tuple[str, str]] = {
            ("user-service", "logs"),
            ("user-service", "deployments"),
            ("user-service", "metrics"),
            ("user-service", "dependencies"),
            ("user-service", "config"),
            ("database", "logs"),
            ("database", "metrics"),
            ("database", "dependencies"),
            ("payment-service", "logs"),
            ("system", "overview"),
            ("system", "recent_changes"),
            ("system", "dependency_graph"),
        }

        # -- Cascading effects ----------------------------------------------
        self.cascading_effects: List[CascadingEffect] = [
            CascadingEffect(
                time_threshold=90,
                service="order-service",
                effect="critical",
                description=(
                    "ALERT ESCALATION: order-service is now CRITICAL. "
                    "Connection pool fully exhausted, no new orders can be created. "
                    "Error rate has risen to 85%."
                ),
            ),
            CascadingEffect(
                time_threshold=150,
                service="api-gateway",
                effect="critical",
                description=(
                    "ALERT ESCALATION: api-gateway is now CRITICAL. "
                    "All downstream services are failing. "
                    "Customer-facing error rate has reached 70%. "
                    "Revenue loss accelerating."
                ),
            ),
            CascadingEffect(
                time_threshold=200,
                service="auth-service",
                effect="down",
                description=(
                    "ALERT ESCALATION: auth-service is DOWN. "
                    "Complete authentication failure — users cannot log in. "
                    "Database connection pool is at 150/150 (fully saturated). "
                    "All authenticated endpoints are returning 401/503."
                ),
            ),
        ]

    # -----------------------------------------------------------------------
    # Abstract method implementations
    # -----------------------------------------------------------------------

    def create_initial_state(self) -> IncidentState:
        """Create a fresh IncidentState for the start of an episode."""
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
        """Create the first observation containing the alert and system overview."""
        return IncidentObservation(
            message=(
                "INCIDENT ALERT: Multiple services reporting high latency and errors.\n\n"
                f"{self.initial_alert}\n\n"
                "You are the on-call SRE. Investigate, diagnose the root cause, and "
                "take corrective action. Time is critical — the situation is worsening."
            ),
            alert_summary=self.initial_alert,
            system_status=self.get_system_status_dict(),
            investigation_result="",
            available_actions=self.get_available_actions(),
            action_result="",
            time_elapsed=0,
            time_budget=self.time_budget,
            hint="Tip: Multiple services share a database connection pool. Check which service is consuming the most connections.",
            done=False,
            reward=0.0,
            metadata={
                "task_id": self.task_id,
                "difficulty": self.difficulty,
                "scenario": self.name,
            },
        )

    def score_resolution(self, actions_taken: List[str]) -> float:
        """Score the agent's corrective actions.

        Scoring tiers:
            1.0 — agent restarted or rolled back user-service (correct fix)
            0.5 — agent drained connections on database (temporary bandaid)
            0.3 — agent restarted payment-service or api-gateway (wrong service)
            0.0 — anything else
        """
        actions_lower = [a.lower() for a in actions_taken]
        joined = " ".join(actions_lower)

        # Best: restart or rollback user-service
        if any(
            ("restart" in a and "user-service" in a)
            or ("rollback" in a and "user-service" in a)
            for a in actions_lower
        ):
            return 1.0

        # Acceptable: drain connections on the database (temporary fix)
        if any(
            "drain_connections" in a and "database" in a
            for a in actions_lower
        ):
            return 0.5

        # Wrong service: restarting a downstream victim
        wrong_targets = {"payment-service", "api-gateway", "order-service", "auth-service"}
        if any(
            "restart" in a and any(t in a for t in wrong_targets)
            for a in actions_lower
        ):
            return 0.3

        return 0.0
