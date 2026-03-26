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
2024-03-15T13:45:22.104Z ERROR [payment-svc-5d8f9a-x2k4m] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-4f8a2c traceId=trace-7d1e3f spanId=span-88a1
  org.postgresql.util.PSQLException: Cannot acquire connection from pool
    Waited: 5,012ms | Pool: active=48/50, idle=0, pending=23
    at org.postgresql.ds.PGPoolingDataSource.getConnection(PGPoolingDataSource.java:112)
    at c.a.payment.db.ConnectionManager.acquire(ConnectionManager.java:67)
    at c.a.payment.handler.PaymentHandler.processPayment(PaymentHandler.java:89)
2024-03-15T13:45:21.891Z ERROR [payment-svc-5d8f9a-x2k4m] c.a.payment.handler.PaymentProcessor - \
ChargeCard failed: context deadline exceeded after 8,012ms requestId=req-3e7b91 traceId=trace-6c2d4e
  customerId=C-88231 orderId=ORD-28471 amount=149.99 currency=USD
  upstream_latency_ms=8012 retry_attempt=3/3
  at c.a.payment.handler.PaymentProcessor.chargeCard(PaymentProcessor.java:156)
2024-03-15T13:45:20.445Z WARN  [payment-svc-5d8f9a-r7j2n] c.a.payment.handler.TransactionManager - \
Transaction timeout after 5,000ms orderId=ORD-28471 requestId=req-3e7b91 traceId=trace-6c2d4e
  state=PENDING_CHARGE elapsed_ms=5012 timeout_ms=5000
  db_pool_status: active=49/50 idle=0 pending_acquire=21
2024-03-15T13:44:58.312Z ERROR [payment-svc-5d8f9a-x2k4m] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-2d6a81 traceId=trace-5b1c3d
  org.postgresql.util.PSQLException: Cannot acquire connection from pool
    Waited: 5,001ms | Pool: active=50/50, idle=0, pending=26
    at org.postgresql.ds.PGPoolingDataSource.getConnection(PGPoolingDataSource.java:112)
2024-03-15T13:44:55.204Z WARN  [payment-svc-5d8f9a-r7j2n] c.a.payment.circuit.CircuitBreaker - \
Circuit breaker OPEN for service=db-write after 12 consecutive failures
  failure_threshold=10 reset_timeout_ms=30000 half_open_max=1
  last_error="PSQLException: Cannot acquire connection from pool"
  window_start=2024-03-15T13:42:55Z window_failures=12
2024-03-15T13:44:31.678Z WARN  [payment-svc-5d8f9a-x2k4m] c.a.payment.handler.PaymentProcessor - \
Retrying payment processing requestId=req-1c5972 traceId=trace-4a0b2c txnId=TXN-9982
  attempt=3/3 backoff_ms=2000 reason="connection_pool_exhausted"
  customerId=C-87994 amount=89.50 currency=USD
2024-03-15T13:44:30.102Z ERROR [payment-svc-5d8f9a-r7j2n] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-1c5972 traceId=trace-4a0b2c
  Pool: active=49/50, idle=0, pending=19
2024-03-15T13:43:45.891Z WARN  [payment-svc-5d8f9a-x2k4m] c.a.payment.handler.PaymentProcessor - \
Retrying payment processing txnId=TXN-9982 attempt=2/3 backoff_ms=1000
2024-03-15T13:43:12.334Z ERROR [payment-svc-5d8f9a-r7j2n] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-0b4861 traceId=trace-390a1b
  Pool: active=50/50, idle=0, pending=17
2024-03-15T13:42:45.112Z INFO  [payment-svc-5d8f9a-x2k4m] c.a.payment.health.HealthCheck - \
Liveness probe: DEGRADED | DB pool utilization 96% (48/50) | response_time_ms=3420
  readiness=false reason="db_pool_saturation"
2024-03-15T13:42:01.567Z ERROR [payment-svc-5d8f9a-r7j2n] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-fa3750 traceId=trace-280912
  Pool: active=50/50, idle=0, pending=14
2024-03-15T13:41:33.204Z WARN  [payment-svc-5d8f9a-x2k4m] c.a.payment.handler.TransactionManager - \
Transaction timeout after 5,000ms orderId=ORD-28464 requestId=req-e92640
2024-03-15T13:40:12.891Z ERROR [payment-svc-5d8f9a-r7j2n] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection requestId=req-d81530 Pool: active=49/50, idle=0, pending=11
2024-03-15T13:39:50.445Z INFO  [payment-svc-5d8f9a-x2k4m] c.a.payment.health.HealthCheck - \
Liveness probe: DEGRADED | DB pool utilization 92% (46/50) | response_time_ms=2840
2024-03-15T13:38:22.102Z WARN  [payment-svc-5d8f9a-r7j2n] c.a.payment.circuit.CircuitBreaker - \
Circuit breaker HALF-OPEN for service=db-write, testing 1 request
  previous_state=OPEN open_duration_ms=30000
2024-03-15T13:37:15.667Z ERROR [payment-svc-5d8f9a-x2k4m] c.a.payment.db.ConnectionManager - \
Failed to acquire database connection Pool: active=47/50, idle=0, pending=8"""

_PAYMENT_SERVICE_METRICS = """\
Service: payment-service (prod-us-east-1)
  pod: payment-svc-5d8f9a-x2k4m | uptime: 847291s
  deployment: v4.1.1 | image: registry.internal/payment-service:v4.1.1
  replicas: 3/3 ready | node_pool: n2-standard-8

  Latency (window=60m):
    p50_latency_ms:       3,200       (baseline: 120)     [+2567%]
    p95_latency_ms:       8,912       (baseline: 340)     [+2521%]
    p99_latency_ms:      12,481       (baseline: 450)     [+2673%]
    p999_latency_ms:     18,204       (baseline: 890)     [+1945%]

  Throughput:
    requests_per_sec:       340       (baseline: 820)     [-58.5%]
    successful_rps:         136       (baseline: 818)     [-83.4%]

  Error Rates:
    error_rate_5xx:        0.6012     (baseline: 0.002)
    error_rate_timeout:    0.4891     (baseline: 0.0003)
    errors_per_sec:        84.2

  Database Connections (shared pool allocation):
    pool_active:            50/50     <- EXHAUSTED
    pool_idle:               0        (baseline: 35)
    pool_pending:           28        <- REQUESTS WAITING
    avg_acquire_ms:       5,200       (baseline: 2ms)     [+259900%]
    acquire_timeout_count: 1,247      (last 15m)

  Resource Utilization:
    cpu_utilization_pct:    40.2
    memory_utilization_pct: 50.1      (2.01 GiB / 4.0 GiB)
    gc_pause_ms_avg:        12        (normal)
    thread_count:          180        (baseline: 120, elevated due to blocked threads)
    open_file_descriptors: 412        (limit: 65536)

  Connection pool timeline (5-min buckets):
    13:00  active= 22  idle=28  pending_acquire=0
    13:05  active= 29  idle=21  pending_acquire=0
    13:10  active= 35  idle=15  pending_acquire=0
    13:15  active= 42  idle= 8  pending_acquire=2
    13:20  active= 47  idle= 3  pending_acquire=8
    13:25  active= 49  idle= 1  pending_acquire=14
    13:30  active= 50  idle= 0  pending_acquire=19   <- pool saturated
    13:35  active= 50  idle= 0  pending_acquire=22
    13:40  active= 50  idle= 0  pending_acquire=25
    13:45  active= 50  idle= 0  pending_acquire=28"""

_PAYMENT_SERVICE_DEPLOYMENTS = """\
+----------------------------------------------------------------------+
| Deployment History: payment-service                                  |
| Cluster: prod-us-east-1 | Namespace: production                     |
| Pipeline: github-actions -> docker-registry -> argocd               |
+----------------------------------------------------------------------+

  v4.1.1  [RUNNING]  deployed 2024-03-14T16:30:00Z (yesterday)
  +--------------------------------------------------------------------+
  | Commit:   abc789f  "fix: align payment button on narrow viewports" |
  | Author:   @jchen (frontend-team)                                   |
  | PR:       #2103 - "Mobile payment form styling fixes"              |
  | Pipeline: Build #8412 -> Stage -> Canary (5%) -> Prod (100%)       |
  | Image:    registry.internal/payment-service:v4.1.1                 |
  | Rollback: v4.1.0                                                   |
  | Changes:  CSS-only change, no backend logic modified               |
  | Tests:    142/142 passed | Coverage: 87.3%                         |
  | Status:   RUNNING - no alerts since deploy                         |
  +--------------------------------------------------------------------+

  v4.1.0  [SUPERSEDED]  deployed 2024-03-11T10:15:00Z (4 days ago)
  +--------------------------------------------------------------------+
  | Commit:   77e2a1b  "feat: apple pay tokenization flow"             |
  | Author:   @mwilson (payments-team)                                 |
  | PR:       #2089 - "Add Apple Pay integration"                      |
  | Status:   STABLE (ran 3 days without issues before v4.1.1)         |
  +--------------------------------------------------------------------+"""

_USER_SERVICE_LOGS = """\
2024-03-15T13:45:30.891Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.BulkSyncJob - \
Sync job still running elapsed=47m12s connections_held=94 batches_completed=487/500
  WARNING: connections are not being released after batch completion
  pool_global_active=142/150 pool_global_idle=0 pool_global_pending=34
  estimated_completion=13:52Z at current rate
2024-03-15T13:42:18.204Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.BulkSyncJob - \
Sync job still running elapsed=44m17s connections_held=94 batches_completed=472/500
  pool_global_active=141/150 starvation_risk=HIGH
2024-03-15T13:40:01.567Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection for batch processing conn_id=conn-094 pool_active=142/150
  batch=487/500 users_in_batch=100 requestId=req-sync-487 traceId=trace-sync-4521
2024-03-15T13:38:22.334Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection for batch processing conn_id=conn-094 pool_active=140/150
  batch=479/500 users_in_batch=100
2024-03-15T13:35:44.102Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.db.SharedPoolMonitor - \
Connection pool utilization critical pool_active=136/150 pool_idle=14
  top_holders: user-service=94, payment-service=24, auth-service=10, order-service=6, api-gateway=2
  alert_threshold=80% current_utilization=90.7%
  WARNING: user-service is dominant consumer (62.7% of shared pool)
2024-03-15T13:32:11.891Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection conn_id=conn-093 pool_active=128/150
  batch=451/500 users_in_batch=100
2024-03-15T13:28:55.445Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Batch processing slower than expected avg_batch_ms=4200 target_batch_ms=1500
  maintaining 8 parallel workers connections_held=91
2024-03-15T13:25:33.204Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection conn_id=conn-091 pool_active=117/150
  batch=412/500 users_in_batch=100
2024-03-15T13:20:01.102Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.BulkSyncJob - \
Sync job still running elapsed=22m connections_held=89 batches_completed=340/500
  WARNING: connections are not being released after batch completion
  pool_global_active=98/150 downstream_impact=possible
2024-03-15T13:15:44.891Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.db.SharedPoolMonitor - \
Connection pool utilization warning pool_active=78/150 pool_idle=72
  top_holders: user-service=62, payment-service=8, auth-service=4, order-service=2, api-gateway=2
  user-service connection growth_rate=+12/min
2024-03-15T13:12:30.667Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection conn_id=conn-078 pool_active=61/150
  batch=310/500 users_in_batch=100
2024-03-15T13:10:05.334Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.WorkerManager - \
Batch processing slow, auto-scaling parallelism workers=4->8
  avg_batch_duration_ms=3800 target_ms=1500
  connection_mode=per_batch reuse_enabled=false
2024-03-15T13:05:33.102Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection conn_id=conn-045 pool_active=45/150
  batch=127/500 users_in_batch=100
2024-03-15T13:02:15.891Z WARN  [user-svc-8a2f1b-k4x9m] c.a.user.sync.WorkerManager - \
Batch processing slow, auto-scaling parallelism workers=2->4
  connection_mode=per_batch reuse_enabled=false
2024-03-15T12:58:03.421Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection for batch processing conn_id=conn-002 pool_active=13/150
  batch=2/500 users_in_batch=100
2024-03-15T12:58:02.891Z DEBUG [user-svc-8a2f1b-k4x9m] c.a.user.sync.BatchProcessor - \
Acquired DB connection for batch processing conn_id=conn-001 pool_active=12/150
  batch=1/500 users_in_batch=100
2024-03-15T12:58:01.204Z INFO  [user-svc-8a2f1b-k4x9m] c.a.user.sync.BulkSyncJob - \
Starting bulk user profile sync batch_id=SYNC-4521 total_batches=500
  Config: parallelism=2, batch_size=100, connection_mode=per_batch
  feature_flag=bulk_sync_enabled=true (NEW in v3.2.0)
  connection_reuse=false  *** BUG: connections will not be returned to pool ***
2024-03-15T12:57:59.567Z INFO  [user-svc-8a2f1b-k4x9m] c.a.user.sync.SyncScheduler - \
Sync scheduler triggered: running new BulkProfileSync task
  cron="0 58 12 * * *" next_run=2024-03-16T12:58:00Z"""

_USER_SERVICE_METRICS = """\
Service: user-service (prod-us-east-1)
  pod: user-svc-8a2f1b-k4x9m | uptime: 2849s (deployed 47m ago)
  deployment: v3.2.0 | image: registry.internal/user-service:v3.2.0
  replicas: 2/2 ready | node_pool: n2-standard-4

  Latency (window=60m):
    p50_latency_ms:       4,200       (baseline: 85)      [+4841%]
    p95_latency_ms:       7,100       (baseline: 240)     [+2858%]
    p99_latency_ms:       8,500       (baseline: 320)     [+2556%]
    p999_latency_ms:     11,800       (baseline: 680)     [+1635%]

  Throughput:
    requests_per_sec:       190       (baseline: 650)     [-70.8%]
    successful_rps:         104       (baseline: 648)     [-83.9%]

  Error Rates:
    error_rate_5xx:        0.4500     (baseline: 0.003)
    error_rate_timeout:    0.3812     (baseline: 0.0002)
    errors_per_sec:        85.5

  Database Connections (shared pool -- THIS SERVICE):
    pool_held_by_svc:       94        *** LEAKING - NEVER RETURNED TO POOL ***
    pool_idle:               0        (baseline: 20)
    avg_acquire_ms:       8,200       (baseline: 3ms)
    NOTE: connections acquired by BulkSyncJob are never released.
          defer conn.Close() is missing in BatchProcessor.processBatch()

  Resource Utilization:
    cpu_utilization_pct:    65.4
    memory_utilization_pct: 70.2      (2.81 GiB / 4.0 GiB)
    gc_pause_ms_avg:        45        (elevated, large object graph from sync)
    goroutine_count:       412        (baseline: 80, elevated due to sync workers)
    open_file_descriptors: 891        (limit: 65536)

  Connection count over time (user-service held connections):
    12:55  held=  0
    12:58  held=  2   <-- sync job started (v3.2.0 BulkSyncJob)
    13:00  held= 12
    13:05  held= 45
    13:10  held= 62
    13:15  held= 78
    13:20  held= 89
    13:25  held= 91
    13:30  held= 93
    13:35  held= 94
    13:40  held= 94   <-- plateau, pool nearly full
    13:45  held= 94"""

_USER_SERVICE_DEPLOYMENTS = """\
+----------------------------------------------------------------------+
| Deployment History: user-service                                     |
| Cluster: prod-us-east-1 | Namespace: production                     |
| Pipeline: github-actions -> docker-registry -> argocd               |
+----------------------------------------------------------------------+

  v3.2.0  [RUNNING]  deployed 2024-03-15T12:55:00Z (50 minutes ago)
  +--------------------------------------------------------------------+
  | Commit:   def456a  "implement parallel batch sync for user profiles"|
  | Author:   @rsingh (backend-team) via ci-bot                        |
  | PR:       #1847 - "Bulk sync to reduce profile staleness"          |
  | Pipeline: Build #7921 -> Stage -> Canary (10%) -> Prod (100%)      |
  | Image:    registry.internal/user-service:v3.2.0                    |
  | Rollback: v3.1.2                                                   |
  | Changes:  NEW FEATURE - bulk user profile sync with parallel       |
  |           processing. First production deployment.                 |
  | Tests:    189/189 passed | Coverage: 82.1%                         |
  |           NOTE: no load/stress tests for connection pool behavior  |
  | Status:   RUNNING - *** CORRELATES WITH INCIDENT ONSET ***         |
  +--------------------------------------------------------------------+

  v3.1.2  [SUPERSEDED]  deployed 2024-03-13T09:00:00Z (2 days ago)
  +--------------------------------------------------------------------+
  | Commit:   8a1bc3e  "fix: handle plus-sign in email local part"     |
  | Author:   @jlee (backend-team)                                     |
  | PR:       #1832 - "Fix email validation regex for edge cases"      |
  | Status:   STABLE (ran 2 days without issues)                       |
  +--------------------------------------------------------------------+

  v3.1.1  [SUPERSEDED]  deployed 2024-03-10T14:20:00Z (5 days ago)
  +--------------------------------------------------------------------+
  | Commit:   4f2e8d1  "perf: optimize user search query with index"   |
  | Author:   @agarwal (backend-team)                                  |
  | Status:   STABLE                                                   |
  +--------------------------------------------------------------------+"""

_USER_SERVICE_DEPENDENCIES = """\
+----------------------------------------------------------------------+
| Service Mesh: user-service dependencies                              |
| Cluster: prod-us-east-1 | Mesh: istio 1.20                         |
+----------------------------------------------------------------------+

  user-service
    |
    +---> database (PostgreSQL 15.4)
    |     Protocol: postgresql | Port: 5432
    |     Connection pool: SHARED pool (150 max connections across all services)
    |     Current usage by user-service: 94 connections (62.7% of shared pool)
    |     Status: *** connections acquired but NOT being returned ***
    |     Longest held connection: 2,847s (conn_id=conn-001, since 12:58:02Z)
    |     Connection leak source: BulkSyncJob -> BatchProcessor.processBatch()
    |
    +---> cache (Redis 7.2)
          Protocol: redis | Port: 6379
          Connection pool: dedicated (max 20)
          Current usage: 8 connections
          Status: healthy | hit_rate=94.2% | latency_p99=3ms"""

_USER_SERVICE_CONFIG = """\
+----------------------------------------------------------------------+
| Configuration: user-service v3.2.0                                   |
| Source: configmap/user-service-config (last applied: 2024-03-15T12:55)|
| Diff vs v3.1.2 shown with [NEW] / [CHANGED] markers                 |
+----------------------------------------------------------------------+

  # Database
  db_pool_max_connections: 100        (per-service soft limit)
  db_pool_min_idle: 5
  db_connection_timeout_ms: 5000
  db_pool_validation_query: "SELECT 1"
  db_pool_max_lifetime_ms: 1800000

  # Bulk Sync (NEW in v3.2.0)
  bulk_sync_enabled: true             [NEW]  <-- enables the sync feature
  bulk_sync_batch_size: 500           [NEW]
  bulk_sync_parallelism: 2            [NEW]  (auto-scaled to 8 under load)
  bulk_sync_connection_reuse: false   [NEW]  <-- *** BUG: should be true ***
                                             Each batch opens a new connection
                                             but never closes it.

  # Application
  profile_cache_ttl_sec: 3600
  request_timeout_ms: 10000
  max_concurrent_requests: 500
  graceful_shutdown_timeout_ms: 30000

  # Feature Flags
  feature.bulk_sync: true             [NEW]
  feature.profile_v2_schema: false"""

_DATABASE_LOGS = """\
2024-03-15T13:45:00.102Z WARN  [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 94.7% active=142/150 idle=8
  Breakdown by client:
    user-service     (10.0.12.45):     94 connections (longest held: 2,847s) *** ANOMALOUS ***
    payment-service  (10.0.12.51):     26 connections (longest held: 12s)
    auth-service     (10.0.12.48):     12 connections (longest held: 8s)
    order-service    (10.0.12.52):      8 connections (longest held: 6s)
    api-gateway      (10.0.12.40):      2 connections (longest held: 1s)
  Pending connection requests: 34
  WARNING: user-service connections show no activity for >10min but remain held
2024-03-15T13:44:30.891Z LOG   [postgres-primary-0] postgresql/stat_activity - \
Active connections by source (pg_stat_activity snapshot):
  user-service:      94 (pids 28401-28494)  state=idle_in_transaction  query=""
  payment-service:   26 (pids 29101-29126)  state=active
  auth-service:      12 (pids 30001-30012)  state=active
  order-service:      8 (pids 30201-30208)  state=active
  api-gateway:        2 (pids 31001-31002)  state=active
2024-03-15T13:40:00.445Z LOG   [postgres-primary-0] postgresql/stat_activity - \
Longest running transaction: user_service.sync_profiles (running for 2,847s, pid 28401)
  query: "UPDATE user_profiles SET last_synced = NOW() WHERE batch_id = $1"
  state: idle_in_transaction | waiting: false
  xact_start: 2024-03-15T12:58:02Z
2024-03-15T13:35:00.204Z WARN  [postgres-primary-0] postgresql/connection_pool - \
89 connections held by user-service (pid range 28401-28489), none returned in last 37 minutes
  connection_mode: persistent (no pooler/pgbouncer in path)
  WARNING: possible connection leak from application code
2024-03-15T13:30:00.102Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 78.0% (117/150 connections active)
2024-03-15T13:25:00.891Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 65.3% (98/150 connections active)
2024-03-15T13:20:00.667Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 52.0% (78/150 connections active)
2024-03-15T13:15:00.445Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 40.7% (61/150 connections active)
2024-03-15T13:10:00.204Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 30.0% (45/150 connections active)
2024-03-15T13:05:00.102Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 18.7% (28/150 connections active)
2024-03-15T13:00:00.891Z LOG   [postgres-primary-0] postgresql/checkpoint - \
Checkpoint complete: wrote 1,247 buffers (7.6%); 0 WAL file(s) added
  write=4.821s sync=0.312s total=5.482s; sync_files=89
2024-03-15T12:58:05.445Z LOG   [postgres-primary-0] postgresql/connection_pool - \
New connections burst detected from user-service (10.0.12.45): 12 connections in 3 seconds
  source_application: user-service/BulkSyncJob
  pool_before=18 pool_after=30
2024-03-15T12:55:00.204Z LOG   [postgres-primary-0] postgresql/connection_pool - \
Pool utilization at 12.0% (18/150 connections active) -- nominal"""

_DATABASE_METRICS = """\
Service: database (PostgreSQL 15.4) (prod-us-east-1)
  pod: postgres-primary-0 | uptime: 2592000s (30d)
  storage: gp3 500GiB | IOPS: 3000 provisioned
  replicas: 1 streaming replica (postgres-replica-0)

  Connection Pool (shared across all services):
    max_connections:       150
    active_connections:    142        *** NEAR CAPACITY (94.7%) ***
    idle_connections:        8
    waiting_connections:    34        (clients blocked waiting for a connection)

  Connections by Service:
    user-service:           94   (62.7%)  *** DOMINANT CONSUMER ***
    payment-service:        26   (17.3%)
    auth-service:           12   ( 8.0%)
    order-service:            8   ( 5.3%)
    api-gateway:              2   ( 1.3%)

  Transaction Stats:
    longest_txn_seconds:  2,847       (user_service.sync_profiles, pid 28401)
    lock_waits_per_sec:      12       (baseline: 0.3)
    deadlocks_total:          0
    xact_commit_per_sec:    420       (baseline: 680)
    xact_rollback_per_sec:   18       (baseline: 2)

  Query Performance:
    query_latency_p50_ms:    18       (baseline: 5)
    query_latency_p99_ms:   280       (baseline: 45)
    rows_fetched_per_sec: 42,000      (elevated due to bulk sync)
    rows_inserted_per_sec:  800       (baseline: 400)
    seq_scan_per_sec:        24       (baseline: 8)

  Resource Utilization:
    cpu_utilization_pct:     75.2
    memory_utilization_pct:  60.4     (shared_buffers: 4GiB, effective_cache: 12GiB)
    disk_iops:              850       (baseline: 200)     [+325%]
    disk_throughput_mbps:    42       (baseline: 12)
    wal_write_mbps:          8.4      (baseline: 2.1)

  Replication:
    replication_lag_ms:       3        (healthy)
    replication_state:       streaming
    replica_apply_rate:      OK

  Pool utilization timeline (5-min buckets):
    12:55  active=  18  idle=132  waiting= 0
    13:00  active=  28  idle=122  waiting= 0
    13:05  active=  45  idle=105  waiting= 0
    13:10  active=  61  idle= 89  waiting= 0
    13:15  active=  78  idle= 72  waiting= 0
    13:20  active=  98  idle= 52  waiting= 2   <- first contention
    13:25  active= 117  idle= 33  waiting= 8
    13:30  active= 128  idle= 22  waiting=15
    13:35  active= 136  idle= 14  waiting=22
    13:40  active= 140  idle= 10  waiting=28
    13:45  active= 142  idle=  8  waiting=34   <- approaching exhaustion"""

_DATABASE_DEPLOYMENTS = """\
+----------------------------------------------------------------------+
| Deployment History: database (PostgreSQL 15.4)                       |
| Cluster: prod-us-east-1 | Managed: Cloud SQL                       |
+----------------------------------------------------------------------+

  No application deployments. Database managed separately.

  Recent configuration changes:
    2024-03-01  Increased max_connections from 100 to 150
                Reason: capacity planning for Q2 traffic growth
                Applied by: @infra-team (change #CHG-4412)

  Last failover:
    2024-02-20  Planned maintenance window
                Primary -> Replica promotion (2.1s downtime)
                Applied by: @dba-oncall (maintenance #MNT-892)

  Replication:
    Mode: streaming | Replicas: 1 | Lag: < 5ms
    Replica: postgres-replica-0 (read-only, healthy)

  Backup:
    Last full backup: 2024-03-15T02:00:00Z (11h ago)
    WAL archiving: continuous, healthy"""

_DATABASE_DEPENDENCIES = """\
+----------------------------------------------------------------------+
| Service Mesh: database dependencies                                  |
| Type: stateful-set | Cluster: prod-us-east-1                        |
+----------------------------------------------------------------------+

  database (PostgreSQL 15.4)
    |
    +--- upstream consumers (services connecting to this database):
    |    |
    |    +-- user-service        94 active connections  *** DOMINANT ***
    |    +-- payment-service     26 active connections
    |    +-- auth-service        12 active connections
    |    +-- order-service        8 active connections
    |    +-- api-gateway          2 active connections
    |    |
    |    Total: 142/150 (94.7%)
    |
    +--- downstream:
         |
         +-- postgres-replica-0  (streaming replication, healthy, lag 3ms)
         +-- pgbouncer:          NOT in use (direct connections from services)
         +-- wal-archiver:       continuous archival to GCS, healthy"""

_AUTH_SERVICE_LOGS = """\
2024-03-15T13:45:10.204Z ERROR [auth-svc-3c7e2d-m8p1q] c.a.auth.validator.TokenValidator - \
Token validation failed: DB query timeout after 5,000ms requestId=req-8f2a41 traceId=trace-9e3b52
  userId=U-442891 tokenType=access_token validationStep=session_lookup
  org.postgresql.util.PSQLException: Query timed out
    Pool: active=12/20, idle=0, pending=4, avg_acquire_ms=4,200
    at c.a.auth.validator.TokenValidator.validateSession(TokenValidator.java:78)
2024-03-15T13:44:52.891Z WARN  [auth-svc-3c7e2d-m8p1q] c.a.auth.db.PoolManager - \
Connection acquire timeout: waited 4,200ms for DB connection requestId=req-7e1930
  pool_active=12/20 pool_idle=0 pool_pending=3
  shared_pool_status: global_active=141/150 (94.0%)
2024-03-15T13:44:33.667Z ERROR [auth-svc-3c7e2d-j5n8r] c.a.auth.validator.TokenValidator - \
Token validation failed: DB query timeout after 5,000ms requestId=req-6d0820 traceId=trace-8d2a41
  userId=U-339012 tokenType=refresh_token
2024-03-15T13:43:58.445Z WARN  [auth-svc-3c7e2d-m8p1q] c.a.auth.db.PoolManager - \
Connection acquire timeout: waited 3,800ms for DB connection requestId=req-5c7710
  pool_active=12/20 pool_idle=0 pool_pending=2
2024-03-15T13:42:11.204Z ERROR [auth-svc-3c7e2d-j5n8r] c.a.auth.session.SessionManager - \
Failed to refresh session: connection pool exhausted requestId=req-4b6600 traceId=trace-7c1930
  sessionId=sess-8a2f1b userId=U-228104
  shared_pool_global_active=139/150
2024-03-15T13:40:45.891Z WARN  [auth-svc-3c7e2d-m8p1q] c.a.auth.db.PoolManager - \
Connection acquire timeout: waited 2,900ms for DB connection requestId=req-3a5500
2024-03-15T13:38:22.667Z WARN  [auth-svc-3c7e2d-j5n8r] c.a.auth.metrics.LatencyMonitor - \
Elevated auth latency: p99=4,800ms (SLA target: 200ms) window=5m
  breach_duration=8m threshold_factor=24x
  impacted_endpoints: /v1/auth/validate, /v1/auth/refresh, /v1/auth/session
2024-03-15T13:35:00.445Z INFO  [auth-svc-3c7e2d-m8p1q] c.a.auth.health.HealthCheck - \
Liveness probe: DEGRADED | DB connection acquire time elevated (p99: 3,200ms)
  readiness=true (degraded) shared_pool_active=136/150
2024-03-15T13:30:00.204Z INFO  [auth-svc-3c7e2d-m8p1q] c.a.auth.health.HealthCheck - \
Liveness probe: DEGRADED | DB connection acquire time elevated (p99: 1,800ms)
2024-03-15T13:25:00.102Z INFO  [auth-svc-3c7e2d-m8p1q] c.a.auth.health.HealthCheck - \
Liveness probe: OK | all checks passing"""

_AUTH_SERVICE_METRICS = """\
Service: auth-service (prod-us-east-1)
  pod: auth-svc-3c7e2d-m8p1q | uptime: 604800s (7d)
  deployment: v2.4.0 | image: registry.internal/auth-service:v2.4.0
  replicas: 2/2 ready | node_pool: n2-standard-4

  Latency (window=60m):
    p50_latency_ms:       2,100       (baseline: 35)      [+5900%]
    p95_latency_ms:       3,800       (baseline: 120)     [+3067%]
    p99_latency_ms:       4,800       (baseline: 150)     [+3100%]
    p999_latency_ms:      6,200       (baseline: 380)     [+1532%]

  Throughput:
    requests_per_sec:       520       (baseline: 1,200)   [-56.7%]
    token_validations/sec:  480       (baseline: 1,100)   [-56.4%]

  Error Rates:
    error_rate_5xx:        0.2500     (baseline: 0.001)
    error_rate_timeout:    0.1890     (baseline: 0.0001)

  Database Connections:
    pool_active:            12/20
    pool_idle:               0        (baseline: 12)
    avg_acquire_ms:       4,200       (baseline: 1ms)
    cache_hit_rate:        0.72       (baseline: 0.95, degraded -- DB-backed sessions timing out)

  Resource Utilization:
    cpu_utilization_pct:    30.1
    memory_utilization_pct: 40.4      (1.62 GiB / 4.0 GiB)"""

_ORDER_SERVICE_LOGS = """\
2024-03-15T13:45:18.102Z ERROR [order-svc-9b4e3f-q2w5t] c.a.order.db.ConnectionManager - \
Failed to acquire DB connection: pool exhausted requestId=req-7c3b21 traceId=trace-8d4c32
  Pool: active=8/10, idle=0, pending=3
  shared_pool_global: active=142/150, waiting=34
  at c.a.order.db.ConnectionManager.acquire(ConnectionManager.java:89)
2024-03-15T13:44:55.891Z WARN  [order-svc-9b4e3f-q2w5t] c.a.order.handler.OrderProcessor - \
Order creation timeout for customerId=C-88231 orderId=ORD-28473 attempt=2/3
  elapsed_ms=5,200 timeout_ms=5,000 payment_status=PENDING
2024-03-15T13:44:12.667Z ERROR [order-svc-9b4e3f-p8r4s] c.a.order.handler.OrderProcessor - \
Order #ORD-28473 failed: downstream payment-service returned HTTP 503
  requestId=req-6b2a10 traceId=trace-7c3b21 customerId=C-88231
  payment_error="Service Unavailable" retry_exhausted=true
  at c.a.order.handler.OrderProcessor.submitPayment(OrderProcessor.java:201)
2024-03-15T13:43:30.445Z WARN  [order-svc-9b4e3f-q2w5t] c.a.order.handler.OrderProcessor - \
Order creation timeout for customerId=C-87994 orderId=ORD-28470
  elapsed_ms=6,100 db_acquire_wait_ms=5,800
2024-03-15T13:42:05.204Z ERROR [order-svc-9b4e3f-p8r4s] c.a.order.db.ConnectionManager - \
Failed to acquire DB connection: waited 6,200ms, max wait 5,000ms
  requestId=req-4a0900 traceId=trace-5b1a10 Pool: active=8/10, idle=0, pending=2
2024-03-15T13:40:33.102Z WARN  [order-svc-9b4e3f-q2w5t] c.a.order.circuit.DownstreamMonitor - \
Downstream payment-service returning errors: 5/5 recent calls failed (100%)
  circuit_state=OPEN last_success=2024-03-15T13:38:22Z
2024-03-15T13:38:00.891Z INFO  [order-svc-9b4e3f-p8r4s] c.a.order.health.HealthCheck - \
Liveness probe: DEGRADED | DB connections scarce | payment-service unhealthy
  readiness=false reason="upstream_dependency_failure"
2024-03-15T13:35:00.667Z INFO  [order-svc-9b4e3f-p8r4s] c.a.order.health.HealthCheck - \
Liveness probe: OK | all checks passing"""

_ORDER_SERVICE_METRICS = """\
Service: order-service (prod-us-east-1)
  pod: order-svc-9b4e3f-q2w5t | uptime: 691200s (8d)
  deployment: v5.0.1 | image: registry.internal/order-service:v5.0.1
  replicas: 2/2 ready | node_pool: n2-standard-4

  Latency (window=60m):
    p50_latency_ms:       2,800       (baseline: 95)      [+2847%]
    p95_latency_ms:       5,100       (baseline: 290)     [+1659%]
    p99_latency_ms:       6,000       (baseline: 380)     [+1479%]
    p999_latency_ms:      8,400       (baseline: 720)     [+1067%]

  Throughput:
    requests_per_sec:       180       (baseline: 450)     [-60.0%]
    orders_created/sec:      45       (baseline: 200)     [-77.5%]
    orders_failed/sec:       55       (baseline: 1)       [+5400%]

  Error Rates:
    error_rate_5xx:        0.3000     (baseline: 0.002)
    error_rate_timeout:    0.2200     (baseline: 0.0003)

  Database Connections:
    pool_active:             8/10
    pool_idle:               0        (baseline: 6)
    avg_acquire_ms:       6,200       (baseline: 2ms)

  Resource Utilization:
    cpu_utilization_pct:    35.2
    memory_utilization_pct: 45.1      (1.80 GiB / 4.0 GiB)"""

_API_GATEWAY_LOGS = """\
2024-03-15T13:45:25.102Z ERROR [api-gw-7f1d4e-a3b6c] c.a.gateway.proxy.UpstreamHandler - \
Upstream auth-service returned HTTP 503 requestId=REQ-8827461 traceId=trace-aa4b5c
  upstream=auth-service:8080/v1/auth/validate method=POST latency_ms=5,201
  client_ip=203.0.113.42 user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)"
  retry_count=3 circuit_state=HALF_OPEN
2024-03-15T13:45:22.891Z WARN  [api-gw-7f1d4e-d9e2f] c.a.gateway.proxy.TimeoutHandler - \
Request REQ-8827459 exceeded timeout (5,200ms): upstream=payment-service
  path=/api/v2/payments/charge method=POST client_ip=198.51.100.18
  upstream_latency_ms=5,200 timeout_ms=5,000
2024-03-15T13:45:15.667Z ERROR [api-gw-7f1d4e-a3b6c] c.a.gateway.proxy.UpstreamHandler - \
Upstream user-service returned HTTP 503 requestId=REQ-8827455 traceId=trace-994a4b
  upstream=user-service:8080/v1/users/profile method=GET latency_ms=8,412
2024-03-15T13:44:58.445Z WARN  [api-gw-7f1d4e-d9e2f] c.a.gateway.proxy.TimeoutHandler - \
Request REQ-8827448 exceeded timeout (5,100ms): upstream=order-service
  path=/api/v2/orders method=POST client_ip=192.0.2.77
2024-03-15T13:44:30.204Z ERROR [api-gw-7f1d4e-a3b6c] c.a.gateway.proxy.UpstreamHandler - \
Upstream payment-service returned HTTP 503 requestId=REQ-8827431 traceId=trace-883930
  upstream=payment-service:8080/v1/payments/charge method=POST latency_ms=5,012
2024-03-15T13:43:50.102Z WARN  [api-gw-7f1d4e-d9e2f] c.a.gateway.retry.RetryBudget - \
Retry budget exhausted for upstream=payment-service: 5/5 retries failed in window=60s
  circuit_state=OPEN reset_timeout_ms=30,000
2024-03-15T13:42:15.891Z WARN  [api-gw-7f1d4e-a3b6c] c.a.gateway.proxy.TimeoutHandler - \
Request REQ-8827390 exceeded timeout: upstream=auth-service latency_ms=5,100
2024-03-15T13:40:00.667Z INFO  [api-gw-7f1d4e-d9e2f] c.a.gateway.health.HealthCheck - \
Liveness probe: DEGRADED | 3/4 upstream services unhealthy
  healthy: [notification-service] unhealthy: [payment-service, user-service, auth-service]
  order-service: DEGRADED
2024-03-15T13:35:00.445Z INFO  [api-gw-7f1d4e-d9e2f] c.a.gateway.health.HealthCheck - \
Liveness probe: DEGRADED | 1/4 upstream services slow
  slow: [payment-service] (p99 > 2,000ms)
2024-03-15T13:30:00.204Z INFO  [api-gw-7f1d4e-d9e2f] c.a.gateway.health.HealthCheck - \
Liveness probe: OK | all upstreams healthy"""

_API_GATEWAY_METRICS = """\
Service: api-gateway (prod-us-east-1)
  pod: api-gw-7f1d4e-a3b6c | uptime: 1209600s (14d)
  deployment: v2.8.3 | image: registry.internal/api-gateway:v2.8.3
  replicas: 4/4 ready | node_pool: n2-standard-8

  Latency (window=60m):
    p50_latency_ms:       2,400       (baseline: 65)      [+3592%]
    p95_latency_ms:       4,200       (baseline: 190)     [+2111%]
    p99_latency_ms:       5,200       (baseline: 250)     [+1980%]
    p999_latency_ms:      8,100       (baseline: 580)     [+1297%]

  Throughput:
    requests_per_sec:       890       (baseline: 2,400)   [-62.9%]
    successful_rps:         578       (baseline: 2,393)   [-75.8%]

  Error Rates:
    error_rate_5xx:        0.3500     (baseline: 0.003)
    upstream_timeout_rate: 0.3200     (baseline: 0.001)
    retry_rate:            0.4500     (baseline: 0.01)

  Connections:
    active_upstream_conns:  240       (baseline: 180)
    request_queue_depth:    120       (baseline: 5)

  Resource Utilization:
    cpu_utilization_pct:    55.3      (elevated due to retry storm)
    memory_utilization_pct: 45.2      (3.62 GiB / 8.0 GiB)

  Upstream error breakdown (last 15m):
    payment-service:   60% of errors   (circuit: OPEN)
    user-service:      22% of errors   (circuit: HALF_OPEN)
    auth-service:      15% of errors   (circuit: HALF_OPEN)
    order-service:      3% of errors   (circuit: CLOSED)"""

_NOTIFICATION_SERVICE_LOGS = """\
2024-03-15T13:45:00.102Z INFO  [notif-svc-4d6a8b-n3p5q] c.a.notification.worker.NotificationWorker - \
Processed 342 notifications in last 5 minutes requestId=batch-notif-9842
  channels: email=201, push=98, sms=43 | success_rate=99.7%
  queue_depth=0 consumer_lag_ms=12
2024-03-15T13:40:00.891Z INFO  [notif-svc-4d6a8b-n3p5q] c.a.notification.worker.NotificationWorker - \
Processed 358 notifications in last 5 minutes
  channels: email=210, push=102, sms=46 | success_rate=99.8%
2024-03-15T13:35:00.667Z INFO  [notif-svc-4d6a8b-n3p5q] c.a.notification.worker.NotificationWorker - \
Processed 361 notifications in last 5 minutes | all channels healthy
2024-03-15T13:30:00.445Z INFO  [notif-svc-4d6a8b-n3p5q] c.a.notification.health.HealthCheck - \
Liveness probe: OK | queue_depth=0 | consumer_count=12 | latency_p99=95ms
2024-03-15T13:25:00.204Z INFO  [notif-svc-4d6a8b-n3p5q] c.a.notification.health.HealthCheck - \
Liveness probe: OK | all checks passing"""

_CACHE_LOGS = """\
2024-03-15T13:45:00.102Z INFO  [redis-primary-0] redis/server - \
Connected clients: 42 (max: 1,000) | Memory: 256.4 MiB / 1,024 MiB (25.0%)
  eviction_policy=allkeys-lru evicted_keys=0
  keyspace: db0=124,521 keys | expires=89,201
2024-03-15T13:40:00.891Z INFO  [redis-primary-0] redis/stats - \
ops_per_sec: 4,200 | hit_rate: 97.2% | miss_rate: 2.8%
  keyspace_hits: 12,481,204 | keyspace_misses: 356,812
  connected_clients: 42 | blocked_clients: 0
2024-03-15T13:35:00.667Z INFO  [redis-primary-0] redis/stats - \
ops_per_sec: 4,180 | hit_rate: 97.1% | evictions: 0
  latency_p99_ms: 2.8 | latency_p999_ms: 4.1
2024-03-15T13:30:00.445Z INFO  [redis-primary-0] redis/health - \
Health check: OK | replication: standalone | persistence: rdb+aof"""

_QUEUE_LOGS = """\
2024-03-15T13:45:00.102Z INFO  [rabbitmq-0] rabbitmq/overview - \
Queues healthy | consumers: 12 | messages_ready: 0 | messages_unacked: 0
  deliver_rate: 68/s | publish_rate: 70/s | ack_rate: 68/s
  memory_used: 128 MiB / 2,048 MiB (6.3%)
2024-03-15T13:40:00.891Z INFO  [rabbitmq-0] rabbitmq/queue - \
Queue "notifications": depth=0 consumers=12 delivered=342/5min
  state=running | durable=true | auto_delete=false
2024-03-15T13:35:00.667Z INFO  [rabbitmq-0] rabbitmq/overview - \
All queues nominal | total_queues: 4 | total_consumers: 18"""

_SYSTEM_OVERVIEW = """\
+======================================================================+
|                    SYSTEM OVERVIEW - INCIDENT IN PROGRESS            |
+======================================================================+
| Cluster: prod-us-east-1 | Region: us-east-1 | Env: production       |
| Kubernetes: v1.28.4 | Istio: 1.20.2 | Nodes: 24                     |
+----------------------------------------------------------------------+

Total services: 9 (4 degraded/critical, 5 healthy)
Shared resource: PostgreSQL connection pool (150 max)
  Current utilization: 142/150 (94.7%) *** CRITICAL ***

Service Health Summary:
  +--------------------+-----------+------------+--------+-------------+
  | Service            | Status    | Latency    | Errors | Connections |
  +--------------------+-----------+------------+--------+-------------+
  | api-gateway        | DEGRADED  | p99: 5.2s  |  35.0% |   2 (gw)    |
  | auth-service       | DEGRADED  | p99: 4.8s  |  25.0% |  12/20      |
  | user-service       | CRITICAL  | p99: 8.5s  |  45.0% |  94 LEAKED  |
  | payment-service    | CRITICAL  | p99: 12.5s |  60.0% |  50/50 FULL |
  | order-service      | DEGRADED  | p99: 6.0s  |  30.0% |   8/10      |
  | notification-svc   | HEALTHY   | p99: 95ms  |   0.5% |   N/A       |
  | database           | DEGRADED  | p99: 280ms |  15.0% | 142/150     |
  | cache (Redis)      | HEALTHY   | p99: 3ms   |   0.1% |  42 ok      |
  | queue (RabbitMQ)   | HEALTHY   | p99: 15ms  |   0.0% |  18 ok      |
  +--------------------+-----------+------------+--------+-------------+

Impact Assessment:
  - Payment processing: DOWN (circuit breaker OPEN)
  - Order creation: FAILING (60% failure rate)
  - User authentication: INTERMITTENT (25% timeout rate)
  - Customer-facing error rate: 35% of all API requests returning 5xx
  - Revenue impact estimate: ~$12,400/hour in lost transactions
  - Affected customers (estimated): 14,200 in last 15 minutes

Timeline:
  12:55  user-service v3.2.0 deployed (PR #1847, bulk sync feature)
  12:58  user-service bulk sync job started (BulkSyncJob SYNC-4521)
  13:10  database connection pool utilization crosses 30%
  13:20  first connection acquire timeouts in payment-service
  13:25  payment-service circuit breaker trips (db-write)
  13:30  order-service starts failing (db pool + payment-service errors)
  13:35  auth-service latency exceeds SLA (p99 > 200ms target)
  13:45  current state - 4 services degraded/critical"""

_SYSTEM_RECENT_CHANGES = """\
+----------------------------------------------------------------------+
| Recent Changes (last 48 hours)                                       |
| Source: ArgoCD + Terraform + ConfigMap audit log                     |
+----------------------------------------------------------------------+

  2024-03-15T12:55:00Z  user-service v3.2.0 deployed
    Author:   @rsingh via ci-bot (PR #1847)
    Change:   "Add bulk user profile sync with parallel processing"
    Impact:   NEW FEATURE - first production run
    Pipeline: Build #7921 -> Stage -> Canary (10%) -> Prod (100%)
    *** CORRELATES WITH INCIDENT START (sync job launched at 12:58) ***

  2024-03-14T16:30:00Z  payment-service v4.1.1 deployed
    Author:   @jchen (frontend-team)
    Change:   "Update payment form CSS for mobile responsiveness"
    Impact:   CSS-only, no backend changes
    Pipeline: Build #8412 -> Stage -> Canary (5%) -> Prod (100%)

  2024-03-14T09:00:00Z  DNS TTL change (infrastructure)
    Author:   @infra-team (change #CHG-4418)
    Change:   Reduced TTL from 300s to 60s for faster failover
    Impact:   Brief resolution blip during propagation (resolved in 45s)

  2024-03-13T09:00:00Z  user-service v3.1.2 deployed
    Author:   @jlee (backend-team)
    Change:   "Fix email validation regex"
    Impact:   Patch, stable for 2 days before v3.2.0"""

_SYSTEM_DEPENDENCY_GRAPH = """\
+======================================================================+
| Service Dependency Graph                                             |
| Cluster: prod-us-east-1 | Mesh: istio 1.20.2                       |
| Protocol: gRPC (inter-service) | PostgreSQL (database)              |
+======================================================================+

  api-gateway (v2.8.3) [DEGRADED]
    |
    +---> auth-service (v2.4.0) [DEGRADED]
    |       +---> database [DEGRADED] (session/token storage)
    |
    +---> user-service (v3.2.0) [CRITICAL]
    |       +---> database [DEGRADED] (user profiles)
    |       |     *** HOLDING 94/150 CONNECTIONS (62.7%) ***
    |       |     *** CONNECTION LEAK: BulkSyncJob ***
    |       +---> cache [HEALTHY] (profile cache)
    |
    +---> payment-service (v4.1.1) [CRITICAL]
    |       +---> database [DEGRADED] (transaction records)
    |       +---> notification-service [HEALTHY] (payment confirmations)
    |
    +---> order-service (v5.0.1) [DEGRADED]
            +---> database [DEGRADED] (order storage)
            +---> payment-service [CRITICAL] (payment processing)

  notification-service (v1.8.0) [HEALTHY]
    +---> queue (RabbitMQ) [HEALTHY] (async delivery)

  Shared Resource:
    database (PostgreSQL 15.4)
      <- auth-service, user-service, payment-service, order-service, api-gateway
      Connection pool: SHARED, 150 max
      Current: 142 active, 8 idle, 34 waiting
      *** user-service consuming 62.7% of pool capacity ***

  cache (Redis 7.2) [HEALTHY]
    <- user-service

  queue (RabbitMQ 3.12) [HEALTHY]
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
        "[P2] FIRING: Multiple Services High Latency\n"
        "Trigger: p99_latency_ms > 5000 for 5m on payment-service (current: 12,481ms)\n"
        "Affected: payment-service, order-service, auth-service, api-gateway\n"
        "Cluster: prod-us-east-1 | Namespace: production\n"
        "Dashboard: https://grafana.internal/d/svc-latency-overview\n"
        "Runbook: https://wiki.internal/runbooks/cascading-latency\n"
        "On-call: @you (primary) | @db-oncall (secondary)\n"
        "Started: 2024-03-15T13:00:00Z | Duration: 45m 22s\n"
        "Correlated alerts: database connection pool warning (13:15Z), "
        "payment-service circuit breaker OPEN (13:25Z)"
    )

    # -- Timing -------------------------------------------------------------
    time_budget: int = 240
    max_steps: int = 25
    min_investigations: int = 3

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
                "+----------------------------------------------------------------------+\n"
                "| Deployment History: api-gateway                                      |\n"
                "| Cluster: prod-us-east-1 | Namespace: production                     |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  No deployments in the last 7 days.\n"
                "\n"
                "  v2.8.3  [RUNNING]  deployed 2024-03-08T11:20:00Z (7 days ago)\n"
                "  +--------------------------------------------------------------------+\n"
                "  | Commit:   f1a2b3c  \"chore: bump envoy proxy to 1.28.1\"             |\n"
                "  | Author:   @infra-team (routine dependency bump)                    |\n"
                "  | Tests:    201/201 passed | Coverage: 91.2%                         |\n"
                "  | Status:   STABLE (7 days, no alerts)                               |\n"
                "  +--------------------------------------------------------------------+"
            ),
            ("api-gateway", "config"): (
                "+----------------------------------------------------------------------+\n"
                "| Configuration: api-gateway v2.8.3                                    |\n"
                "| Source: configmap/api-gateway-config (last applied: 2024-03-08)      |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  upstream_timeout_ms: 5000\n"
                "  max_retries: 3\n"
                "  retry_backoff_ms: 500\n"
                "  circuit_breaker_threshold: 5\n"
                "  circuit_breaker_reset_ms: 30000\n"
                "  rate_limit_rps: 5000\n"
                "  max_concurrent_streams: 1000\n"
                "  idle_timeout_ms: 60000\n"
                "\n"
                "  NOTE: No recent config changes. Last modified 2024-03-08."
            ),
            ("payment-service", "dependencies"): (
                "+----------------------------------------------------------------------+\n"
                "| Service Mesh: payment-service dependencies                           |\n"
                "| Cluster: prod-us-east-1 | Mesh: istio 1.20                         |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  payment-service\n"
                "    |\n"
                "    +---> database (PostgreSQL 15.4)\n"
                "    |     Protocol: postgresql | Port: 5432\n"
                "    |     Connection pool: SHARED (50 allocated of 150 total)\n"
                "    |     Status: pool exhausted (50/50 allocated in use)\n"
                "    |\n"
                "    +---> notification-service\n"
                "    |     Protocol: gRPC | Port: 9090\n"
                "    |     Status: healthy | latency_p99: 95ms\n"
                "    |\n"
                "    +---> external: stripe-api (payment gateway)\n"
                "          Protocol: HTTPS | Endpoint: api.stripe.com\n"
                "          Status: healthy | latency_p99: 120ms\n"
                "          All external dependencies healthy."
            ),
            ("payment-service", "config"): (
                "+----------------------------------------------------------------------+\n"
                "| Configuration: payment-service v4.1.1                                |\n"
                "| Source: configmap/payment-service-config (last applied: 2024-03-14)  |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  db_pool_max_connections: 50\n"
                "  transaction_timeout_ms: 5000\n"
                "  retry_max_attempts: 3\n"
                "  retry_backoff_ms: 1000\n"
                "  stripe_api_timeout_ms: 3000\n"
                "  stripe_api_key: sk-****-redacted\n"
                "  idempotency_key_ttl_sec: 86400\n"
                "\n"
                "  NOTE: No recent config changes. Last modified 2024-03-14 (CSS deploy)."
            ),
            ("auth-service", "deployments"): (
                "+----------------------------------------------------------------------+\n"
                "| Deployment History: auth-service                                     |\n"
                "| Cluster: prod-us-east-1 | Namespace: production                     |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  No deployments in the last 7 days.\n"
                "\n"
                "  v2.4.0  [RUNNING]  deployed 2024-03-06T14:30:00Z (9 days ago)\n"
                "  +--------------------------------------------------------------------+\n"
                "  | Commit:   9c8d7e6  \"feat: add OAuth2 PKCE support\"                 |\n"
                "  | Author:   @security-team                                           |\n"
                "  | Tests:    156/156 passed | Coverage: 89.4%                         |\n"
                "  | Status:   STABLE (9 days, no alerts)                               |\n"
                "  +--------------------------------------------------------------------+"
            ),
            ("auth-service", "config"): (
                "+----------------------------------------------------------------------+\n"
                "| Configuration: auth-service v2.4.0                                   |\n"
                "| Source: configmap/auth-service-config (last applied: 2024-03-06)     |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  db_pool_max_connections: 20\n"
                "  token_ttl_sec: 3600\n"
                "  refresh_token_ttl_sec: 604800\n"
                "  session_cache_enabled: true\n"
                "  session_cache_ttl_sec: 300\n"
                "  bcrypt_rounds: 12\n"
                "  oauth2_pkce_required: true\n"
                "\n"
                "  NOTE: No recent config changes. Last modified 2024-03-06."
            ),
            ("order-service", "deployments"): (
                "+----------------------------------------------------------------------+\n"
                "| Deployment History: order-service                                    |\n"
                "| Cluster: prod-us-east-1 | Namespace: production                     |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  No deployments in the last 7 days.\n"
                "\n"
                "  v5.0.1  [RUNNING]  deployed 2024-03-07T10:45:00Z (8 days ago)\n"
                "  +--------------------------------------------------------------------+\n"
                "  | Commit:   b2c3d4e  \"fix: order status webhook retry logic\"         |\n"
                "  | Author:   @backend-team                                            |\n"
                "  | Tests:    178/178 passed | Coverage: 85.7%                         |\n"
                "  | Status:   STABLE (8 days, no alerts)                               |\n"
                "  +--------------------------------------------------------------------+"
            ),
            ("notification-service", "metrics"): (
                "Service: notification-service (prod-us-east-1)\n"
                "  pod: notif-svc-4d6a8b-n3p5q | uptime: 1728000s (20d)\n"
                "  deployment: v1.8.0 | image: registry.internal/notification-service:v1.8.0\n"
                "  replicas: 2/2 ready | node_pool: n2-standard-2\n"
                "\n"
                "  Latency (window=60m):\n"
                "    p50_latency_ms:        80       (baseline: 75)\n"
                "    p95_latency_ms:        92       (baseline: 88)\n"
                "    p99_latency_ms:       100       (baseline: 95)\n"
                "\n"
                "  Throughput:\n"
                "    notifications/sec:      68       (baseline: 72)     [-5.6%]\n"
                "\n"
                "  Error Rates:\n"
                "    error_rate:            0.005     (baseline: 0.003)\n"
                "\n"
                "  Resource Utilization:\n"
                "    cpu_utilization_pct:    20.1\n"
                "    memory_utilization_pct: 30.2     (604 MiB / 2.0 GiB)\n"
                "\n"
                "  Status: HEALTHY - all metrics within normal range"
            ),
            ("cache", "metrics"): (
                "Service: cache / Redis 7.2 (prod-us-east-1)\n"
                "  pod: redis-primary-0 | uptime: 2592000s (30d)\n"
                "  mode: standalone | persistence: rdb+aof\n"
                "\n"
                "  Performance:\n"
                "    connected_clients:      42\n"
                "    ops_per_sec:          4,200\n"
                "    hit_rate:             97.2%      (baseline: 97.5%)\n"
                "    miss_rate:             2.8%\n"
                "    latency_p99_ms:         3        (baseline: 2.8)\n"
                "    evictions:              0\n"
                "\n"
                "  Memory:\n"
                "    memory_used:          256 MiB / 1,024 MiB (25.0%)\n"
                "    mem_fragmentation_ratio: 1.02\n"
                "\n"
                "  Status: HEALTHY - all metrics nominal"
            ),
            ("queue", "metrics"): (
                "Service: queue / RabbitMQ 3.12 (prod-us-east-1)\n"
                "  pod: rabbitmq-0 | uptime: 2592000s (30d)\n"
                "  cluster: standalone | vhost: production\n"
                "\n"
                "  Queues:\n"
                "    total_queues:           4\n"
                "    consumers:             18\n"
                "    messages_ready:         0\n"
                "    messages_unacked:       0\n"
                "\n"
                "  Throughput:\n"
                "    deliver_rate:          68/s\n"
                "    publish_rate:          70/s\n"
                "    ack_rate:              68/s\n"
                "\n"
                "  Memory:\n"
                "    memory_used:          128 MiB / 2,048 MiB (6.3%)\n"
                "\n"
                "  Status: HEALTHY - all queues draining normally"
            ),
            ("network", "metrics"): (
                "+----------------------------------------------------------------------+\n"
                "| Network Metrics                                                      |\n"
                "| Cluster: prod-us-east-1 | CNI: Calico 3.27 | Mesh: istio 1.20      |\n"
                "+----------------------------------------------------------------------+\n"
                "\n"
                "  DNS:\n"
                "    resolution_latency_p99_ms:  2     (normal)\n"
                "    NOTE: Brief DNS resolution blip at 10:15 UTC today (3 hours ago),\n"
                "    lasted 45 seconds, fully resolved. Unrelated to current incident.\n"
                "    coredns pods: 2/2 healthy\n"
                "\n"
                "  Inter-service:\n"
                "    packet_loss:              0.00%\n"
                "    tcp_retransmit_rate:      0.01%   (normal)\n"
                "    istio_sidecar_latency_ms: 0.8     (normal)\n"
                "\n"
                "  Load Balancer:\n"
                "    health: all backends registered\n"
                "    active_connections: 2,847\n"
                "    draining: 0\n"
                "\n"
                "  Status: HEALTHY - no network-level issues detected"
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
                    "[P1] ESCALATION: order-service is now CRITICAL\n"
                    "Connection pool fully exhausted (10/10 active, 0 idle, 12 pending)\n"
                    "No new orders can be created. Error rate has risen to 85%.\n"
                    "Revenue impact accelerating: ~$18,600/hour\n"
                    "Dashboard: https://grafana.internal/d/order-svc-critical"
                ),
            ),
            CascadingEffect(
                time_threshold=150,
                service="api-gateway",
                effect="critical",
                description=(
                    "[P1] ESCALATION: api-gateway is now CRITICAL\n"
                    "All downstream services are failing. Circuit breakers OPEN on 4/4 upstreams.\n"
                    "Customer-facing error rate has reached 70%. Request queue depth: 840.\n"
                    "Revenue loss accelerating: ~$31,200/hour\n"
                    "StatusPage updated: Major Outage\n"
                    "Dashboard: https://grafana.internal/d/api-gw-critical"
                ),
            ),
            CascadingEffect(
                time_threshold=200,
                service="auth-service",
                effect="down",
                description=(
                    "[P0] ESCALATION: auth-service is DOWN\n"
                    "Complete authentication failure -- users cannot log in.\n"
                    "Database connection pool is at 150/150 (fully saturated).\n"
                    "All authenticated endpoints are returning 401/503.\n"
                    "Active sessions cannot be validated. Session cache expired.\n"
                    "Incident commander paged. War room opened.\n"
                    "Dashboard: https://grafana.internal/d/auth-svc-down"
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
                "=== INCIDENT ALERT ===\n\n"
                f"{self.initial_alert}\n\n"
                "---\n"
                "You are the on-call SRE. This incident has been open for 45 minutes and is "
                "actively worsening. Multiple services share infrastructure resources. "
                "Investigate, diagnose the root cause, and take corrective action before "
                "cascading failures cause a full outage."
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
