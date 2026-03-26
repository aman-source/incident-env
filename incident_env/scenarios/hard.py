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
2024-03-15T14:32:01.117Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_20184 provider=provider-A latency_ms=11 \
claims=[sub,iss,exp,iat,roles] traceId=trace-4d8a2f requestId=req-00a1b2 spanId=span-7c91
2024-03-15T14:32:01.312Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_44920 provider=provider-C latency_ms=9 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-7f1b3e requestId=req-00a1b3 spanId=span-8d02
2024-03-15T14:32:02.044Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_38127 provider=provider-A latency_ms=13 \
claims=[sub,iss,exp,iat,roles] traceId=trace-a91c4d requestId=req-00a1b4 spanId=span-9e13
2024-03-15T14:32:02.518Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_72841 provider=provider-A latency_ms=10 \
claims=[sub,iss,exp,iat,roles] traceId=trace-b02d5e requestId=req-00a1b5 spanId=span-0f24
2024-03-15T14:32:03.201Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_55301 provider=provider-C latency_ms=15 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-c13e6f requestId=req-00a1b6 spanId=span-1a35
2024-03-15T14:32:03.784Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_73219 provider=provider-C latency_ms=8 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-d24f70 requestId=req-00a1b7 spanId=span-2b46
2024-03-15T14:32:04.105Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_12847 provider=provider-A latency_ms=11 \
claims=[sub,iss,exp,iat,roles] traceId=trace-e35a81 requestId=req-00a1b8 spanId=span-3c57
2024-03-15T14:32:04.622Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_33918 provider=provider-A latency_ms=9 \
claims=[sub,iss,exp,iat,roles] traceId=trace-f46b92 requestId=req-00a1b9 spanId=span-4d68
2024-03-15T14:32:05.338Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_28471 provider=provider-A latency_ms=12 \
claims=[sub,iss,exp,iat,roles] traceId=trace-057ca3 requestId=req-00a1c0 spanId=span-5e79
2024-03-15T14:32:05.791Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_61845 provider=provider-C latency_ms=10 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-168db4 requestId=req-00a1c1 spanId=span-6f8a
2024-03-15T14:32:06.204Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_90184 provider=provider-A latency_ms=12 \
claims=[sub,iss,exp,iat,roles] traceId=trace-279ec5 requestId=req-00a1c2 spanId=span-709b
2024-03-15T14:32:06.517Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_48271 provider=provider-C latency_ms=9 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-38afd6 requestId=req-00a1c3 spanId=span-81ac
2024-03-15T14:32:07.004Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_52093 provider=provider-A latency_ms=14 \
claims=[sub,iss,exp,iat,roles] traceId=trace-49b0e7 requestId=req-00a1c4 spanId=span-92bd
2024-03-15T14:32:07.418Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_19472 provider=provider-A latency_ms=7 \
claims=[sub,iss,exp,iat,roles] traceId=trace-5ac1f8 requestId=req-00a1c5 spanId=span-a3ce
2024-03-15T14:32:08.102Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_44192 provider=provider-C latency_ms=8 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-6bd209 requestId=req-00a1c6 spanId=span-b4df
2024-03-15T14:32:08.533Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_73891 provider=provider-A latency_ms=10 \
claims=[sub,iss,exp,iat,roles] traceId=trace-7ce31a requestId=req-00a1c7 spanId=span-c5e0
2024-03-15T14:32:09.217Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_88214 provider=provider-A latency_ms=11 \
claims=[sub,iss,exp,iat,roles] traceId=trace-8df42b requestId=req-00a1c8 spanId=span-d6f1
2024-03-15T14:32:09.891Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_91823 \
error=schema_mismatch field=realm_access traceId=trace-9e053c requestId=req-00a1c9 spanId=span-e702
2024-03-15T14:32:10.014Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_91823 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-9e053c requestId=req-00a1c9 spanId=span-e702 httpStatus=500
2024-03-15T14:32:10.498Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_66501 provider=provider-A latency_ms=9 \
claims=[sub,iss,exp,iat,roles] traceId=trace-af164d requestId=req-00a1d0 spanId=span-f813
2024-03-15T14:32:10.901Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_33782 provider=provider-C latency_ms=13 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-b0275e requestId=req-00a1d1 spanId=span-0924
2024-03-15T14:32:11.244Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_42918 provider=provider-A latency_ms=10 \
claims=[sub,iss,exp,iat,roles] traceId=trace-c1386f requestId=req-00a1d2 spanId=span-1a35
2024-03-15T14:32:11.712Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_77341 provider=provider-A latency_ms=8 \
claims=[sub,iss,exp,iat,roles] traceId=trace-d2497a requestId=req-00a1d3 spanId=span-2b46
2024-03-15T14:32:12.108Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_29104 provider=provider-C latency_ms=12 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-e35a8b requestId=req-00a1d4 spanId=span-3c57
2024-03-15T14:32:12.590Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_51283 provider=provider-A latency_ms=7 \
claims=[sub,iss,exp,iat,roles] traceId=trace-f46b9c requestId=req-00a1d5 spanId=span-4d68
2024-03-15T14:32:13.077Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_84629 provider=provider-C latency_ms=11 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-057cad requestId=req-00a1d6 spanId=span-5e79
2024-03-15T14:32:13.421Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_37104 provider=provider-A latency_ms=14 \
claims=[sub,iss,exp,iat,roles] traceId=trace-168dbe requestId=req-00a1d7 spanId=span-6f8a
2024-03-15T14:32:14.005Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_67234 \
error=schema_mismatch field=realm_access traceId=trace-279ecf requestId=req-00a1d8 spanId=span-709b
2024-03-15T14:32:14.018Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_67234 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-279ecf requestId=req-00a1d8 spanId=span-709b httpStatus=500
2024-03-15T14:32:14.412Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_95127 provider=provider-A latency_ms=9 \
claims=[sub,iss,exp,iat,roles] traceId=trace-38afd0 requestId=req-00a1d9 spanId=span-81ac
2024-03-15T14:32:15.087Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_18493 provider=provider-C latency_ms=10 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-49b0e1 requestId=req-00a1e0 spanId=span-92bd
2024-03-15T14:32:15.498Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_62817 provider=provider-A latency_ms=8 \
claims=[sub,iss,exp,iat,roles] traceId=trace-5ac1f2 requestId=req-00a1e1 spanId=span-a3ce"""

# Second-time auth-service logs: more errors visible, shows the pattern
# more clearly. Still no explicit "provider-B" label — just more error lines
# on the canary pod. Agent needs to correlate with deployment/config.
_AUTH_LOGS_SECOND_CHECK = """\
2024-03-15T14:35:01.204Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_20184 provider=provider-A latency_ms=11 \
claims=[sub,iss,exp,iat,roles] traceId=trace-4d8a2f requestId=req-01b2c3 spanId=span-7c91
2024-03-15T14:35:01.518Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_83921 \
error=schema_mismatch field=realm_access traceId=trace-aa1b2c requestId=req-01b2c4 spanId=span-dd01
2024-03-15T14:35:01.521Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_83921 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-aa1b2c requestId=req-01b2c4 spanId=span-dd01 httpStatus=500
2024-03-15T14:35:02.044Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_38127 provider=provider-A latency_ms=13 \
claims=[sub,iss,exp,iat,roles] traceId=trace-bb2c3d requestId=req-01b2c5 spanId=span-ee12
2024-03-15T14:35:02.397Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_47182 \
error=schema_mismatch field=realm_access traceId=trace-cc3d4e requestId=req-01b2c6 spanId=span-ff23
2024-03-15T14:35:02.401Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_47182 error="claim structure validation failed: \
unexpected nested field in realm_access" \
details={"field":"realm_access.nested_permissions","expected":"absent","got":"object{4 keys}"} \
traceId=trace-cc3d4e requestId=req-01b2c6 spanId=span-ff23 httpStatus=500
2024-03-15T14:35:03.201Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_55301 provider=provider-C latency_ms=15 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-dd4e5f requestId=req-01b2c7 spanId=span-0034
2024-03-15T14:35:03.784Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_73219 provider=provider-C latency_ms=8 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-ee5f60 requestId=req-01b2c8 spanId=span-1145
2024-03-15T14:35:04.112Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_91823 \
error=schema_mismatch field=realm_access traceId=trace-ff6071 requestId=req-01b2c9 spanId=span-2256
2024-03-15T14:35:04.115Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_91823 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-ff6071 requestId=req-01b2c9 spanId=span-2256 httpStatus=500
2024-03-15T14:35:04.622Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_12847 provider=provider-A latency_ms=11 \
claims=[sub,iss,exp,iat,roles] traceId=trace-007182 requestId=req-01b2d0 spanId=span-3367
2024-03-15T14:35:05.338Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_33918 provider=provider-A latency_ms=9 \
claims=[sub,iss,exp,iat,roles] traceId=trace-118293 requestId=req-01b2d1 spanId=span-4478
2024-03-15T14:35:05.741Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_67234 \
error=schema_mismatch field=realm_access traceId=trace-2293a4 requestId=req-01b2d2 spanId=span-5589
2024-03-15T14:35:05.744Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_67234 error="claim structure validation failed: \
unexpected nested field in realm_access" \
details={"field":"realm_access.nested_permissions","expected":"absent","got":"object{4 keys}"} \
traceId=trace-2293a4 requestId=req-01b2d2 spanId=span-5589 httpStatus=500
2024-03-15T14:35:06.204Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_28471 provider=provider-A latency_ms=12 \
claims=[sub,iss,exp,iat,roles] traceId=trace-33a4b5 requestId=req-01b2d3 spanId=span-669a
2024-03-15T14:35:06.601Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_82156 \
error=schema_mismatch field=realm_access traceId=trace-44b5c6 requestId=req-01b2d4 spanId=span-77ab
2024-03-15T14:35:06.604Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_82156 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-44b5c6 requestId=req-01b2d4 spanId=span-77ab httpStatus=500
2024-03-15T14:35:07.087Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_61845 provider=provider-C latency_ms=10 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-55c6d7 requestId=req-01b2d5 spanId=span-88bc
2024-03-15T14:35:07.498Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_90184 provider=provider-A latency_ms=12 \
claims=[sub,iss,exp,iat,roles] traceId=trace-66d7e8 requestId=req-01b2d6 spanId=span-99cd
2024-03-15T14:35:08.102Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_16392 \
error=schema_mismatch field=realm_access traceId=trace-77e8f9 requestId=req-01b2d7 spanId=span-aade
2024-03-15T14:35:08.105Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_16392 error="claim structure validation failed: \
unexpected nested field in realm_access" \
details={"field":"realm_access.nested_permissions","expected":"absent","got":"object{4 keys}"} \
traceId=trace-77e8f9 requestId=req-01b2d7 spanId=span-aade httpStatus=500
2024-03-15T14:35:08.533Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_48271 provider=provider-C latency_ms=9 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-88f90a requestId=req-01b2d8 spanId=span-bbef
2024-03-15T14:35:09.217Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_52093 provider=provider-A latency_ms=14 \
claims=[sub,iss,exp,iat,roles] traceId=trace-990a1b requestId=req-01b2d9 spanId=span-cc00
2024-03-15T14:35:09.601Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_39471 \
error=schema_mismatch field=realm_access traceId=trace-aa1b2d requestId=req-01b2e0 spanId=span-dd11
2024-03-15T14:35:09.604Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_39471 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-aa1b2d requestId=req-01b2e0 spanId=span-dd11 httpStatus=500
2024-03-15T14:35:10.087Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_19472 provider=provider-A latency_ms=7 \
claims=[sub,iss,exp,iat,roles] traceId=trace-bb2c3e requestId=req-01b2e1 spanId=span-ee22
2024-03-15T14:35:10.498Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_73891 provider=provider-A latency_ms=10 \
claims=[sub,iss,exp,iat,roles] traceId=trace-cc3d4f requestId=req-01b2e2 spanId=span-ff33
2024-03-15T14:35:11.102Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_58214 \
error=schema_mismatch field=realm_access traceId=trace-dd4e50 requestId=req-01b2e3 spanId=span-0044
2024-03-15T14:35:11.105Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_58214 error="claim structure validation failed: \
unexpected nested field in realm_access" \
details={"field":"realm_access.nested_permissions","expected":"absent","got":"object{4 keys}"} \
traceId=trace-dd4e50 requestId=req-01b2e3 spanId=span-0044 httpStatus=500
2024-03-15T14:35:11.498Z INFO  [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_44192 provider=provider-C latency_ms=8 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-ee5f61 requestId=req-01b2e4 spanId=span-1155
2024-03-15T14:35:12.087Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_33782 provider=provider-C latency_ms=13 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-ff6072 requestId=req-01b2e5 spanId=span-2266
2024-03-15T14:35:12.498Z WARN  [auth-svc-canary-x9k2m] c.a.auth.claims.ClaimsValidator - \
Claim validation warning: unexpected nested structure in JWT claims userId=usr_71029 \
error=schema_mismatch field=realm_access traceId=trace-007183 requestId=req-01b2e6 spanId=span-3377
2024-03-15T14:35:12.501Z ERROR [auth-svc-canary-x9k2m] c.a.auth.handler.TokenValidator - \
Token validation failed userId=usr_71029 error="claim structure validation failed" \
details={"field":"realm_access","expected":"flat","got":"nested"} \
traceId=trace-007183 requestId=req-01b2e6 spanId=span-3377 httpStatus=500
2024-03-15T14:35:13.204Z INFO  [auth-svc-stable-7b4f9] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_42918 provider=provider-A latency_ms=10 \
claims=[sub,iss,exp,iat,roles] traceId=trace-118294 requestId=req-01b2e7 spanId=span-4488
2024-03-15T14:35:13.712Z INFO  [auth-svc-stable-a3m8k] c.a.auth.handler.TokenValidator - \
Token validated successfully userId=usr_84629 provider=provider-C latency_ms=11 \
claims=[sub,iss,exp,iat,permissions] traceId=trace-2293a5 requestId=req-01b2e8 spanId=span-5599"""

# Auth-service metrics: shows per-pod breakdown but NO per-provider breakdown.
# The agent can see canary pod has higher errors but not WHY.
_AUTH_METRICS = """\
Service: auth-service (prod-us-east-1) — canary deployment active

  Replicas: 3 (2 stable + 1 canary)
  Deployment: v5.0.4-stable (90%) / v5.1.0-canary (10%)

  Aggregate Metrics (last 15m, scraped from Prometheus):
    http_requests_total:           2,412 req/s
    http_request_duration_seconds:
      p50:                         42ms
      p95:                         320ms
      p99:                         812ms       (baseline: 95ms) ← ELEVATED
    http_requests_errors_total:
      5xx_rate:                    0.0821      (baseline: 0.002) ← ELEVATED
      4xx_rate:                    0.031       (nominal)
    process_cpu_seconds_total:     50.1%
    process_resident_memory_bytes: 1,847 MB / 4,096 MB limit (45.1%)
    go_goroutines:                 2,841
    grpc_connections_active:       4,812
    connection_pool_usage_pct:     62.0%

  Per-Pod Breakdown (envoy sidecar metrics):
    auth-svc-stable-7b4f9 (traffic weight: ~45%):
      envoy_http_downstream_rq_5xx:   0.0012    (nominal)
      envoy_http_downstream_rq_total: 1,085 req/s
      http_request_duration_p99:      88ms
      container_cpu_usage_seconds:    38.2%
      container_memory_rss:           1,721 MB

    auth-svc-stable-a3m8k (traffic weight: ~45%):
      envoy_http_downstream_rq_5xx:   0.0009    (nominal)
      envoy_http_downstream_rq_total: 1,087 req/s
      http_request_duration_p99:      92ms
      container_cpu_usage_seconds:    39.7%
      container_memory_rss:           1,764 MB

    auth-svc-canary-x9k2m (traffic weight: ~10%):
      envoy_http_downstream_rq_5xx:   0.8214    ← CRITICAL
      envoy_http_downstream_rq_total: 240 req/s
      http_request_duration_p99:      1,891ms
      container_cpu_usage_seconds:    78.4%     (error-handling overhead)
      container_memory_rss:           2,134 MB

  Canary Analysis (Kayenta / automated):
    canary_health_score:   12 / 100    ← FAILING
    auto_promote_blocked:  true (error_rate 82.14% >> threshold 1%)
    baseline_comparison:   SIGNIFICANT_REGRESSION"""

_AUTH_DEPLOYMENTS = """\
Deployment History: auth-service (prod-us-east-1)

  ┌─ CANARY (active) ─────────────────────────────────────────────────────
  │ Version:      v5.1.0-canary
  │ Deployed:     2024-03-15T14:10:00Z (25 min ago)
  │ Strategy:     Canary (10% traffic → auth-svc-canary-x9k2m)
  │ Triggered by: ci-bot via merged PR #2341
  │ Commit:       7a8b9c0 "migrate to structured claims validation library v3"
  │ Author:       sarah@company.com
  │ Reviewers:    @sarah-auth, @mike-platform (both approved)
  │ CI Pipeline:  ✓ unit tests (847/847) | ✓ integration (312/312) | ✓ lint | ✓ SAST
  │ Image:        registry.internal/auth-service:v5.1.0-canary@sha256:a9f8c2e1...
  │ Traffic:      10% canary / 90% stable
  │ Auto-promote: blocked (error_rate 82.14% >> threshold 1%)
  │ Rollback:     instant via traffic shift (kubectl set traffic auth-service --canary=0)
  │
  │ Changelog:
  │   - Replaced legacy token parser (pkg/auth/legacy_parser.go) with
  │     structured claims library (github.com/org/claims-validator v3.0.1)
  │   - New library enforces stricter schema validation for JWT claim structures
  │   - Intended to improve compliance with OAuth 2.1 spec
  │   - Disabled legacy_parser_fallback (was: true → now: false)
  │   - Added nested_claims_support flag (new in v5.1.0)
  └───────────────────────────────────────────────────────────────────────

  ┌─ STABLE (current baseline) ───────────────────────────────────────────
  │ Version:    v5.0.4
  │ Deployed:   2024-03-10T08:00:00Z (5 days ago)
  │ Triggered:  ci-bot via PR #2298
  │ Commit:     3d4e5f6 "add structured logging for OAuth provider metrics"
  │ Changes:    Minor logging improvements, no behavioral changes
  │ Pods:       auth-svc-stable-7b4f9, auth-svc-stable-a3m8k
  │ Status:     STABLE
  └───────────────────────────────────────────────────────────────────────

  Previous Releases:
    v5.0.3 — deployed 2024-03-03T14:30:00Z (12 days ago)
      Commit: b2c3d4e "rate limiter tuning: increased quota 500→800 rps"
      Status: SUPERSEDED

    v5.0.2 — deployed 2024-02-28T10:00:00Z (16 days ago)
      Commit: e5f6a7b "fix connection pool leak on timeout path"
      Status: SUPERSEDED"""

_AUTH_DEPENDENCIES = """\
auth-service (v5.1.0-canary / v5.0.4-stable) — Dependency Graph

  Downstream Dependencies (services auth-service calls):
  ├─→ database (PostgreSQL 15.4) [latency: 4ms | errors: 0.0% | pool: 48/100 | circuit: CLOSED]
  ├─→ cache (Redis 7.2)          [latency: 1.1ms | errors: 0.0% | hit_rate: 94.2% | circuit: CLOSED]
  ├─→ provider-A (external OAuth) [status: HEALTHY | last_check: 2m ago | p99: 45ms]
  ├─→ provider-B (external OAuth) [status: HEALTHY | last_check: 2m ago | p99: 52ms]
  │   └─ Note: Had 45min outage on 2024-03-10 (5 days ago, fully resolved — RCA: provider-side DNS)
  └─→ provider-C (external OAuth) [status: HEALTHY | last_check: 2m ago | p99: 38ms]

  Upstream Callers (services that call auth-service):
  ├── api-gateway       [all authenticated /api/* routes pass through auth-service]
  ├── order-service     [validates user tokens before processing orders]
  └── payment-service   [validates tokens for payment authorization]

  Service Mesh (Istio):
    mTLS:               enforced (STRICT mode)
    Circuit Breaker:    CLOSED (error threshold 50%, window 60s)
    Retry Policy:       2 retries, 25ms/100ms/250ms backoff
    Timeout:            2000ms per request"""

# Config reveals the critical info: claims_validation_mode changed, legacy
# fallback disabled. This is where provider-B's non-standard claim becomes
# relevant. But the agent has to READ this and connect the dots.
_AUTH_CONFIG = """\
auth-service/config.yaml — Runtime Configuration (mounted via ConfigMap auth-svc-config-v143)

  canary:
    enabled: true
    version: v5.1.0-canary
    traffic_pct: 10
    pod_selector: "app=auth-service,track=canary"
    auto_promote_after: 7200s       # 2 hours
    error_threshold: 0.01           # 1% error rate max for promotion
    rollback_on_breach: false       # manual rollback required

  token_validation:
    claims_validation_mode: strict     # ← changed from "permissive" in v5.1.0
    nested_claims_support: true        # ← NEW in v5.1.0
    legacy_parser_fallback: false      # ← DISABLED in v5.1.0 (was: true)
    token_cache_ttl_sec: 300
    max_token_age_sec: 3600
    supported_providers: [provider-A, provider-B, provider-C]

  rate_limiting:
    per_provider_rps_limit: 800
    global_rps_limit: 3000
    burst_allowance: 1.5x

  circuit_breaker:
    enabled: true
    error_threshold_pct: 50
    window_sec: 60
    half_open_after_sec: 30
    state: CLOSED

  --- DIFF from v5.0.4 (stable) → v5.1.0 (canary) ---
  - claims_validation_mode: permissive
  + claims_validation_mode: strict
  + nested_claims_support: true
  - legacy_parser_fallback: true
  + legacy_parser_fallback: false

  Known compatibility notes (from internal wiki, last updated 2024-02-15):
    - provider-B uses non-standard nested_permissions inside realm_access claim
    - Old parser (legacy_parser.go) handled this gracefully via fallback path
    - New claims-validator v3 rejects non-RFC-compliant nested structures by default
    - This was documented in AUTHSVC-4421 but not flagged during PR #2341 review"""

_ORDER_LOGS = """\
2024-03-15T14:33:01.117Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_91823 status=500 upstream=auth-service \
retry=1/3 traceId=trace-o1a2b3 requestId=req-ord001 spanId=span-o101
2024-03-15T14:33:01.498Z INFO  [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation succeeded on retry userId=usr_91823 retryAttempt=2 \
(routed to different pod) traceId=trace-o1a2b3 requestId=req-ord001 spanId=span-o102
2024-03-15T14:33:02.204Z INFO  [order-svc-7d8e9f] c.a.order.handler.OrderHandler - \
Order created orderId=ord_88291 userId=usr_44192 total=42.99 currency=USD \
paymentMethod=card_visa latency_ms=184 traceId=trace-o2b3c4 requestId=req-ord002
2024-03-15T14:33:03.087Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_67234 status=500 upstream=auth-service \
retry=1/3 traceId=trace-o3c4d5 requestId=req-ord003 spanId=span-o201
2024-03-15T14:33:03.401Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_67234 status=500 upstream=auth-service \
retry=2/3 traceId=trace-o3c4d5 requestId=req-ord003 spanId=span-o202
2024-03-15T14:33:04.012Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_67234 status=500 upstream=auth-service \
retry=3/3 traceId=trace-o3c4d5 requestId=req-ord003 spanId=span-o203
2024-03-15T14:33:04.015Z ERROR [order-svc-7d8e9f] c.a.order.handler.OrderHandler - \
Order creation failed userId=usr_67234 error="upstream auth-service returned 500 after \
3 retries" traceId=trace-o3c4d5 requestId=req-ord003 spanId=span-o204 httpStatus=502
2024-03-15T14:33:05.338Z INFO  [order-svc-a1b2c3] c.a.order.handler.OrderHandler - \
Order created orderId=ord_88292 userId=usr_55301 total=18.50 currency=USD \
paymentMethod=card_mastercard latency_ms=162 traceId=trace-o4d5e6 requestId=req-ord004
2024-03-15T14:33:06.204Z INFO  [order-svc-7d8e9f] c.a.order.handler.OrderHandler - \
Order created orderId=ord_88293 userId=usr_33918 total=127.00 currency=USD \
paymentMethod=paypal latency_ms=201 traceId=trace-o5e6f7 requestId=req-ord005
2024-03-15T14:33:07.087Z ERROR [order-svc-a1b2c3] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_82156 status=500 upstream=auth-service \
retry=1/3 traceId=trace-o6f708 requestId=req-ord006 spanId=span-o301
2024-03-15T14:33:07.401Z ERROR [order-svc-a1b2c3] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_82156 status=500 upstream=auth-service \
retry=2/3 traceId=trace-o6f708 requestId=req-ord006 spanId=span-o302
2024-03-15T14:33:07.812Z WARN  [order-svc-a1b2c3] c.a.order.client.AuthClient - \
Auth validation succeeded on retry userId=usr_82156 retryAttempt=3 \
traceId=trace-o6f708 requestId=req-ord006 spanId=span-o303
2024-03-15T14:33:08.204Z INFO  [order-svc-a1b2c3] c.a.order.handler.OrderHandler - \
Order created orderId=ord_88294 userId=usr_82156 total=65.20 currency=USD \
paymentMethod=card_visa latency_ms=340 traceId=trace-o6f708 requestId=req-ord006
2024-03-15T14:33:09.087Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_16392 status=500 upstream=auth-service \
retry=1/3 traceId=trace-o7a819 requestId=req-ord007 spanId=span-o401
2024-03-15T14:33:09.401Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_16392 status=500 upstream=auth-service \
retry=2/3 traceId=trace-o7a819 requestId=req-ord007 spanId=span-o402
2024-03-15T14:33:10.012Z ERROR [order-svc-7d8e9f] c.a.order.client.AuthClient - \
Auth validation failed userId=usr_16392 status=500 upstream=auth-service \
retry=3/3 traceId=trace-o7a819 requestId=req-ord007 spanId=span-o403
2024-03-15T14:33:10.015Z ERROR [order-svc-7d8e9f] c.a.order.handler.OrderHandler - \
Order creation failed userId=usr_16392 error="upstream auth-service returned 500 after \
3 retries" traceId=trace-o7a819 requestId=req-ord007 spanId=span-o404 httpStatus=502"""

_ORDER_METRICS = """\
Service: order-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:           850 req/s
    http_request_duration_seconds:
      p50:                         180ms
      p99:                         900ms       (baseline: 250ms) ← ELEVATED
    http_requests_errors_total:
      5xx_rate:                    0.072       (baseline: 0.003) ← ELEVATED
    process_cpu_seconds_total:     32.4%
    process_resident_memory_bytes: 1,562 MB / 4,096 MB limit (38.1%)

  Error Breakdown (last 15m):
    auth_validation_failures:      68%   ← upstream auth-service 500s
    timeout_errors:                30%   ← auth retry timeouts
    internal_errors:               2%    (nominal baseline)
    database_errors:               0%

  Dependency Health (as observed by order-service via circuit breakers):
    auth-service:   DEGRADED (envoy reporting intermittent 500s, circuit: HALF_OPEN)
    database:       HEALTHY  (circuit: CLOSED, latency p99: 8ms)
    payment-service: HEALTHY (circuit: CLOSED, latency p99: 95ms)"""

_API_GATEWAY_LOGS = """\
2024-03-15T14:34:01.117Z WARN  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Upstream error status=500 service=auth-service requestId=req_a8f21 \
path=/api/v2/orders method=POST clientIp=10.42.8.91 traceId=trace-gw01a
2024-03-15T14:34:01.498Z INFO  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_b2c43 path=/api/v2/users/profile method=GET \
status=200 latency_ms=62 upstream=user-service clientIp=10.42.12.44 traceId=trace-gw02b
2024-03-15T14:34:02.204Z INFO  [gw-prod-8d9e0f] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_d4e65 path=/api/v2/search method=GET \
status=200 latency_ms=85 upstream=search-service clientIp=10.42.5.18 traceId=trace-gw03c
2024-03-15T14:34:02.601Z WARN  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Upstream error status=500 service=auth-service requestId=req_f6g87 \
path=/api/v2/payments method=POST clientIp=10.42.9.73 traceId=trace-gw04d
2024-03-15T14:34:03.087Z INFO  [gw-prod-8d9e0f] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_h8i09 path=/api/v2/orders method=GET \
status=200 latency_ms=340 upstream=order-service clientIp=10.42.11.22 traceId=trace-gw05e
2024-03-15T14:34:03.498Z INFO  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_j0k12 path=/api/v2/users/settings method=GET \
status=200 latency_ms=55 upstream=user-service clientIp=10.42.7.88 traceId=trace-gw06f
2024-03-15T14:34:04.204Z ERROR [gw-prod-8d9e0f] c.a.gateway.proxy.UpstreamHandler - \
Request failed requestId=req_l2m34 path=/api/v2/orders method=POST \
status=502 error="auth-service retries exhausted (3/3)" \
clientIp=10.42.14.56 traceId=trace-gw07a upstreamLatency_ms=2012
2024-03-15T14:34:04.601Z INFO  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_n4o56 path=/api/v2/recommendations method=GET \
status=200 latency_ms=210 upstream=recommendation-service clientIp=10.42.3.91 traceId=trace-gw08b
2024-03-15T14:34:05.087Z INFO  [gw-prod-8d9e0f] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_p6q78 path=/api/v2/search method=GET \
status=200 latency_ms=79 upstream=search-service clientIp=10.42.6.44 traceId=trace-gw09c
2024-03-15T14:34:05.498Z INFO  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_r8s90 path=/api/v2/analytics/events method=POST \
status=200 latency_ms=42 upstream=analytics-service clientIp=10.42.10.12 traceId=trace-gw10d
2024-03-15T14:34:06.204Z WARN  [gw-prod-8d9e0f] c.a.gateway.proxy.UpstreamHandler - \
Upstream error status=500 service=auth-service requestId=req_t1u23 \
path=/api/v2/orders method=POST clientIp=10.42.8.33 traceId=trace-gw11e
2024-03-15T14:34:06.601Z INFO  [gw-prod-5a6b7c] c.a.gateway.proxy.UpstreamHandler - \
Request completed requestId=req_v4w56 path=/api/v2/billing/invoices method=GET \
status=200 latency_ms=95 upstream=billing-service clientIp=10.42.13.77 traceId=trace-gw12f"""

_API_GATEWAY_METRICS = """\
Service: api-gateway (prod-us-east-1) — Envoy front-proxy

  Aggregate Metrics (last 15m, Prometheus):
    envoy_http_downstream_rq_total:   12,000 req/s
    http_request_duration_seconds:
      p50:                            120ms
      p95:                            680ms
      p99:                            1,200ms    (baseline: 350ms) ← ELEVATED
    envoy_http_downstream_rq_5xx:     0.081      (baseline: 0.004) ← ELEVATED
    process_cpu_seconds_total:        45.2%
    process_resident_memory_bytes:    3,312 MB / 8,192 MB limit (40.4%)

  Error Attribution by Upstream (envoy cluster stats):
    auth-service:       95.2%    ← PRIMARY SOURCE
    order-service:      3.1%     (cascading from auth-service)
    payment-service:    1.7%     (auth pre-check failures)
    user-service:       0.0%
    search-service:     0.0%
    billing-service:    0.0%
    analytics-service:  0.0%
    recommendation-svc: 0.0%

  Rate Limiting:
    global_rps_limit:   18,000   (updated via config-service at 14:05Z)
    current_rps:        12,000
    throttled_requests: 0"""

_API_GATEWAY_DEPLOYMENTS = """\
Deployment History: api-gateway (prod-us-east-1)

  ┌─ STABLE (current) ───────────────────────────────────────────────────
  │ Version:    v3.8.2
  │ Deployed:   2024-03-08T12:00:00Z (7 days ago)
  │ Triggered:  ci-bot via PR #2187
  │ Commit:     f1e2d3c "upgrade HTTP/2 multiplexing, minor header parsing fix"
  │ CI:         ✓ unit tests | ✓ integration | ✓ load test (50K rps)
  │ Image:      registry.internal/api-gateway:v3.8.2@sha256:c4d5e6f7...
  │ Status:     STABLE — no recent changes
  └───────────────────────────────────────────────────────────────────────

  Note: Config-service pushed rate-limit update at 14:05Z (v142→v143),
        but this was a rate-limit increase only (15K→18K rps), no behavioral change."""

_RECOMMENDATION_LOGS = """\
2024-03-15T14:28:00.204Z INFO  [rec-svc-a4b5c6] c.a.recommendation.pipeline.MLPipeline - \
Starting daily model retraining batch jobId=ml-retrain-20240315 \
schedule="0 14 * * *" model=collaborative-filtering-v4 traceId=trace-ml01
2024-03-15T14:28:01.087Z INFO  [rec-svc-a4b5c6] c.a.recommendation.pipeline.DataLoader - \
Loading training data from data-lake: 2.3M user interactions (last 7 days) \
source=s3://ml-data-lake/interactions/ format=parquet traceId=trace-ml01
2024-03-15T14:28:02.498Z INFO  [rec-svc-a4b5c6] c.a.recommendation.pipeline.FeatureExtractor - \
Feature extraction started estimatedDuration=25min totalRecords=2,300,000 \
features=[user_embedding,item_embedding,interaction_type,temporal_weight] traceId=trace-ml01
2024-03-15T14:28:15.204Z INFO  [rec-svc-a4b5c6] c.a.recommendation.pipeline.FeatureExtractor - \
Feature extraction progress: 12% (280K/2.3M records) elapsed=13s \
throughput=21,538 records/sec memoryUsed=3,412MB traceId=trace-ml01
2024-03-15T14:29:00.087Z WARN  [rec-svc-a4b5c6] c.a.recommendation.monitor.ResourceMonitor - \
CPU utilization at 85.2%, approaching autoscale threshold (90%) \
container=rec-svc-a4b5c6 node=ip-10-42-8-191 traceId=trace-ml01
2024-03-15T14:30:00.204Z WARN  [rec-svc-a4b5c6] c.a.recommendation.monitor.ResourceMonitor - \
CPU utilization at 92.3%, autoscale threshold breached \
container=rec-svc-a4b5c6 node=ip-10-42-8-191 traceId=trace-ml01
2024-03-15T14:30:01.087Z INFO  [rec-svc-a4b5c6] c.a.recommendation.autoscaler.HPAController - \
HPA triggered: scaling from 3 to 5 replicas (targetCPU=70%, currentCPU=92.3%) \
event=ScaleUp reason=CPUUtilizationAboveTarget traceId=trace-hpa01
2024-03-15T14:30:02.498Z INFO  [rec-svc-a4b5c6] c.a.recommendation.autoscaler.HPAController - \
New pods starting: rec-svc-d7e8f9, rec-svc-g0h1i2 \
scheduledTo=[ip-10-42-9-44, ip-10-42-9-88] traceId=trace-hpa01
2024-03-15T14:31:00.204Z INFO  [rec-svc-d7e8f9] c.a.recommendation.autoscaler.HPAController - \
Pods ready, readiness probes passing, traffic rebalancing in progress \
activeReplicas=5 traceId=trace-hpa01
2024-03-15T14:32:00.087Z INFO  [rec-svc-a4b5c6] c.a.recommendation.health.HealthCheck - \
Health check passed: serving normally p99_latency=195ms \
requestRate=3,200rps errorRate=0.010 activeModel=cf-v4.2.1 traceId=trace-hc01
2024-03-15T14:33:00.498Z INFO  [rec-svc-a4b5c6] c.a.recommendation.pipeline.FeatureExtractor - \
Feature extraction progress: 48% (1.1M/2.3M records) elapsed=5m \
throughput=19,841 records/sec memoryUsed=4,891MB traceId=trace-ml01
2024-03-15T14:34:00.204Z INFO  [rec-svc-a4b5c6] c.a.recommendation.monitor.ResourceMonitor - \
CPU utilization at 71.2% (post-scale), within target range \
replicas=5 node_spread=[ip-10-42-8-191, ip-10-42-9-44, ip-10-42-9-88] traceId=trace-ml01"""

_RECOMMENDATION_METRICS = """\
Service: recommendation-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:           3,200 req/s
    http_request_duration_seconds:
      p50:                         95ms
      p99:                         200ms      (baseline: 180ms — slight elevation during retrain)
    http_requests_errors_total:
      5xx_rate:                    0.010      (nominal — these are timeout-on-retrain, self-healing)
    process_cpu_seconds_total:     92.3%      ← HIGH (ML retraining job, autoscaler responding)
    process_resident_memory_bytes: 4,891 MB / 8,192 MB limit (59.7%)
    active_replicas:               5 (scaled from 3 at 14:30Z)

  Autoscaler Status (HPA):
    trigger:               cpu > 90% sustained for 60s
    current_state:         SCALING_COMPLETE
    target_cpu:            70%
    current_cpu:           71.2% (post-scale)
    min_replicas:          3
    max_replicas:          8
    last_scale_event:      2024-03-15T14:30:01Z (5 min ago)
    cooldown_remaining:    55s"""

_RECOMMENDATION_DEPLOYMENTS = """\
Deployment History: recommendation-service (prod-us-east-1)

  ┌─ STABLE (current) ───────────────────────────────────────────────────
  │ Version:    v2.14.0
  │ Deployed:   2024-03-05T09:00:00Z (10 days ago)
  │ Triggered:  ci-bot via PR #1945
  │ Commit:     a8b9c0d "updated feature store connector, improved cold-start caching"
  │ CI:         ✓ unit tests | ✓ integration | ✓ model accuracy regression
  │ Image:      registry.internal/recommendation-service:v2.14.0@sha256:b1c2d3e4...
  │ Status:     STABLE — no recent changes
  └───────────────────────────────────────────────────────────────────────

  Previous:
    v2.13.8 — deployed 2024-02-25T16:00:00Z
      Commit: d4e5f6a "handle missing user preference data gracefully"
      Status: SUPERSEDED

  Note: Daily ML retraining job runs at 14:00 UTC via CronJob (not a code deployment).
        Current job started at 14:28Z, expected completion ~14:55Z. CPU spike is expected."""

# RED HERRING: database slow query
_DATABASE_LOGS = """\
2024-03-15T14:10:22.004Z INFO  [postgres-primary-0] LOG:  checkpoint starting: time
2024-03-15T14:10:23.117Z INFO  [postgres-primary-0] LOG:  checkpoint complete: \
wrote 847 buffers (0.6%); 0 WAL file(s) added, 0 removed, 2 recycled; \
write=1.012 s, sync=0.084 s, total=1.113 s; sync files=42, longest=0.014 s, average=0.002 s; \
distance=4218 kB, estimate=5120 kB
2024-03-15T14:14:45.891Z WARN  [postgres-primary-0] LOG:  duration: 852.441 ms  statement: \
SELECT u.id, u.email, u.created_at, p.plan_type, p.renewal_date, \
t.total_orders, t.total_revenue \
FROM users u \
JOIN plans p ON u.plan_id = p.id \
JOIN (SELECT user_id, COUNT(*) as total_orders, SUM(amount) as total_revenue \
FROM orders WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY user_id) t ON u.id = t.user_id \
WHERE u.last_active > NOW() - INTERVAL '30 days' \
ORDER BY t.total_revenue DESC LIMIT 10000
2024-03-15T14:14:46.204Z INFO  [postgres-primary-0] LOG:  query originated from \
analytics-service (10.42.4.22:54312) — scheduled daily report, cron 14:14 UTC \
application_name=analytics-batch-reporter
2024-03-15T14:30:00.087Z INFO  [postgres-primary-0] LOG:  automatic vacuum of table \
"public.auth_sessions": index scans: 1 \
pages: 0 removed, 4218 remain, 0 skipped due to pins, 0 skipped frozen \
tuples: 1204 removed, 284721 remain, 0 are dead but not yet removable
2024-03-15T14:32:00.204Z INFO  [postgres-primary-0] LOG:  checkpoint starting: time
2024-03-15T14:32:01.087Z INFO  [postgres-primary-0] LOG:  checkpoint complete: \
wrote 312 buffers (0.2%); 0 WAL file(s) added, 0 removed, 1 recycled; \
write=0.812 s, sync=0.041 s, total=0.883 s
2024-03-15T14:33:00.498Z INFO  [postgres-primary-0] LOG:  duration: 45.221 ms  statement: \
SELECT * FROM token_revocations WHERE provider=$1 AND expires_at > NOW()
2024-03-15T14:34:00.204Z INFO  [postgres-primary-0] LOG:  connection stats: \
142 active / 500 max / 0 waiting / 358 idle \
oldest_transaction_age=0s autovacuum_workers=1/3"""

_DATABASE_METRICS = """\
Service: database (PostgreSQL 15.4, prod-us-east-1)

  Aggregate Metrics (last 15m, pg_stat / node_exporter):
    pg_stat_activity_count:       142 active / 500 max_connections
    pg_stat_activity_waiting:     0
    pg_query_duration_seconds:
      p50:                        4ms
      p99:                        12ms       (nominal)
    pg_stat_bgwriter_buffers:     312 (last checkpoint)
    pg_stat_user_tables_seq_scan: 0 (no seq scans — indexes healthy)
    node_cpu_seconds_total:       48.0%
    node_memory_MemUsed_bytes:    52.3%       (26.2 GB / 50 GB)
    node_disk_io_pct:             28.0%
    pg_replication_lag_seconds:   0.000       (synchronous replica)
    pg_locks_count:               0 exclusive / 4 shared (nominal)
    pg_stat_activity_deadlocks:   0 (last hour)
    slow_queries_15m:             1 (852ms — analytics daily report at 14:14Z, expected)

  Replication:
    primary:    postgres-primary-0 (10.42.2.10)
    replica:    postgres-replica-0 (10.42.2.11) — lag: 0ms — SYNC
    backup:     last full backup 2024-03-15T06:00:00Z (8h ago) — OK"""

_CACHE_LOGS = """\
2024-03-15T14:32:00.204Z INFO  [redis-primary-0] c.a.cache.server.RedisServer - \
Memory usage: 1.2GB / 4.0GB (28.4%) maxmemory_policy=allkeys-lru \
connected_clients=89 blocked_clients=0 used_cpu_sys=8.21 used_cpu_user=4.18
2024-03-15T14:33:00.087Z INFO  [redis-primary-0] c.a.cache.server.RedisServer - \
Key evictions last 60s: 0 expired_keys=142 keyspace_hits=8412 keyspace_misses=517 \
hit_rate=94.2% instantaneous_ops_per_sec=14,821
2024-03-15T14:34:00.498Z INFO  [redis-primary-0] c.a.cache.server.RedisServer - \
Replication: role=master connected_slaves=1 repl_offset=284712944 \
slave0: ip=10.42.3.12 port=6379 state=online offset=284712944 lag=0"""

_CACHE_METRICS = """\
Service: cache (Redis 7.2, prod-us-east-1)

  Aggregate Metrics (last 15m, redis_exporter):
    redis_commands_processed_total: 14,821 ops/s
    redis_command_duration_seconds:
      p50:                          0.4ms
      p99:                          1.1ms     (nominal)
    redis_keyspace_hits_ratio:      94.2%
    redis_memory_used_bytes:        1.2 GB / 4.0 GB limit (28.4%)
    redis_connected_clients:        89
    redis_evicted_keys_total:       0 (last 15m)
    redis_blocked_clients:          0
    node_cpu_seconds_total:         12.4%
    replication_lag_seconds:        0.000"""

# RED HERRING: CDN DNS change (2 hours ago, resolved)
_CDN_LOGS = """\
2024-03-15T12:15:00.204Z INFO  [cdn-edge-mgr-01] c.a.cdn.config.DNSManager - \
DNS configuration update applied: updated CNAME records for static.example.com \
oldTarget=cdn-old.cloudfront.net newTarget=cdn-v2.cloudfront.net \
changeId=C0RRJQ1B2EXXYZ propagation=global traceId=trace-cdn01
2024-03-15T12:15:01.087Z INFO  [cdn-edge-mgr-01] c.a.cdn.config.DNSManager - \
TTL propagation started (TTL=300s) edgeLocations=47 \
expectedCompletion=2024-03-15T12:20:00Z traceId=trace-cdn01
2024-03-15T12:20:00.498Z INFO  [cdn-edge-mgr-01] c.a.cdn.config.DNSManager - \
TTL propagation complete. All 47 edge nodes updated. \
verificationStatus=PASSED errors=0 traceId=trace-cdn01
2024-03-15T12:25:00.204Z INFO  [cdn-edge-mgr-01] c.a.cdn.health.HealthCheck - \
Post-change health check: all edge nodes responding normally \
hitRate=98.7% avgLatency_ms=18 errorRate=0.001 traceId=trace-cdn02
2024-03-15T14:30:00.087Z INFO  [cdn-edge-mgr-01] c.a.cdn.health.HealthCheck - \
Routine health check: OK hitRate=98.7% avgLatency_ms=19 \
bandwidthUtilization=34.2% traceId=trace-cdn03"""

# RED HERRING: config-service pushed updates recently
_CONFIG_SERVICE_LOGS = """\
2024-03-15T14:05:00.204Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Config push initiated operator=@platform-team reason="rate-limit capacity increase" \
changeId=cfg-push-20240315-001 etcd_revision=v142→v143 traceId=trace-cfg01
2024-03-15T14:05:01.087Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Pushing updated rate-limit configs to targets=[api-gateway, order-service, \
payment-service, auth-service] pushStrategy=sequential_with_ack \
rollbackOnFailure=false traceId=trace-cfg01
2024-03-15T14:05:02.204Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Target acknowledged: api-gateway configKey=rate_limit_global \
oldValue=15000 newValue=18000 ackLatency_ms=42 traceId=trace-cfg01
2024-03-15T14:05:02.601Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Target acknowledged: order-service configKey=rate_limit_per_user \
oldValue=50 newValue=60 ackLatency_ms=38 traceId=trace-cfg01
2024-03-15T14:05:03.087Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Target acknowledged: payment-service configKey=rate_limit_per_user \
oldValue=30 newValue=40 ackLatency_ms=44 traceId=trace-cfg01
2024-03-15T14:05:03.498Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Target acknowledged: auth-service configKey=rate_limit_global \
oldValue=2500 newValue=3000 ackLatency_ms=41 traceId=trace-cfg01
2024-03-15T14:05:04.204Z INFO  [cfg-svc-b2c3d4] c.a.config.pusher.ConfigPusher - \
Push complete: all 4/4 services acknowledged successfully \
totalDuration_ms=4201 configVersion=v143 traceId=trace-cfg01
2024-03-15T14:05:04.498Z INFO  [cfg-svc-b2c3d4] c.a.config.audit.AuditLogger - \
Audit log written: changeId=cfg-push-20240315-001 operator=@platform-team \
targets=4 status=SUCCESS s3://audit-logs/config/2024/03/15/cfg-push-001.json
2024-03-15T14:06:00.204Z INFO  [cfg-svc-b2c3d4] c.a.config.health.PostPushVerifier - \
Post-push health check: all target services report config v143 active \
verification=[api-gateway:OK, order-service:OK, payment-service:OK, auth-service:OK]
2024-03-15T14:34:00.087Z INFO  [cfg-svc-b2c3d4] c.a.config.health.HealthCheck - \
Routine health check: OK etcd_cluster=healthy leader=etcd-0 \
configVersion=v143 lastPush=29m ago status=IDLE"""

_CONFIG_SERVICE_METRICS = """\
Service: config-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:           120 req/s
    http_request_duration_seconds:
      p50:                         12ms
      p99:                         35ms       (nominal)
    http_requests_errors_total:
      5xx_rate:                    0.000
    process_cpu_seconds_total:     8.2%
    process_resident_memory_bytes: 738 MB / 4,096 MB limit (18.0%)

  Config Push Stats:
    last_push:             2024-03-15T14:05:04Z (30 min ago)
    last_push_targets:     api-gateway, order-service, payment-service, auth-service
    last_push_status:      SUCCESS (all 4 targets acknowledged)
    last_push_change:      rate-limit capacity increase
    config_version:        v143
    etcd_cluster_health:   HEALTHY (3/3 members)"""

_CONFIG_SERVICE_DEPLOYMENTS = """\
Deployment History: config-service (prod-us-east-1)

  ┌─ STABLE (current) ───────────────────────────────────────────────────
  │ Version:    v1.4.2
  │ Deployed:   2024-03-01T10:00:00Z (14 days ago)
  │ Triggered:  ci-bot via PR #1812
  │ Commit:     c2d3e4f "added audit logging for config pushes"
  │ CI:         ✓ unit tests | ✓ integration | ✓ etcd compatibility
  │ Image:      registry.internal/config-service:v1.4.2@sha256:d3e4f5a6...
  │ Status:     STABLE
  └───────────────────────────────────────────────────────────────────────

  Recent Config Pushes (these are data changes, not code deployments):
    2024-03-15T14:05:04Z: rate-limit config to 4 services (v142→v143) — SUCCESS
    2024-03-14T09:00:00Z: feature-flag update to api-gateway (v141→v142) — SUCCESS
    2024-03-12T16:00:00Z: timeout config update to order-service (v140→v141) — SUCCESS"""

# RED HERRING: payment-service cert renewal warning
_PAYMENT_SERVICE_LOGS = """\
2024-03-15T14:15:00.204Z WARN  [pay-svc-c3d4e5] c.a.payment.tls.CertificateManager - \
TLS certificate for payment-gateway.internal expires in 14 days (2024-03-29T00:00:00Z) \
serialNumber=3A:7B:2C:8D:4E:9F issuer=internal-ca-prod autoRenewal=scheduled \
renewalDate=2024-03-22T00:00:00Z jiraTicket=INFRA-9012 traceId=trace-pay01
2024-03-15T14:15:01.087Z WARN  [pay-svc-c3d4e5] c.a.payment.tls.CertificateManager - \
mTLS cert for payment-processor.external renewal pending \
currentCert_validUntil=2024-03-29 autoRenewal=scheduled processor=stripe \
traceId=trace-pay01
2024-03-15T14:32:00.498Z INFO  [pay-svc-c3d4e5] c.a.payment.handler.PaymentHandler - \
Payment processed paymentId=pay_44291 userId=usr_55301 amount=18.50 currency=USD \
processor=stripe status=SUCCESS latency_ms=78 traceId=trace-pay02 \
fraudScore=0.02 riskLevel=LOW
2024-03-15T14:33:00.204Z INFO  [pay-svc-f6a7b8] c.a.payment.handler.PaymentHandler - \
Payment processed paymentId=pay_44292 userId=usr_33918 amount=127.00 currency=USD \
processor=stripe status=SUCCESS latency_ms=82 traceId=trace-pay03 \
fraudScore=0.01 riskLevel=LOW
2024-03-15T14:34:00.087Z WARN  [pay-svc-c3d4e5] c.a.payment.client.AuthClient - \
Payment auth pre-check failed userId=usr_82156 upstream=auth-service \
status=500 willRetry=true retryPolicy=exponential_backoff \
traceId=trace-pay04 spanId=span-pay01
2024-03-15T14:34:01.498Z INFO  [pay-svc-c3d4e5] c.a.payment.handler.PaymentHandler - \
Payment processed paymentId=pay_44293 userId=usr_82156 amount=65.20 currency=USD \
processor=stripe status=SUCCESS latency_ms=195 traceId=trace-pay04 \
note="auth retry succeeded on attempt 2" fraudScore=0.03 riskLevel=LOW
2024-03-15T14:34:30.204Z INFO  [pay-svc-f6a7b8] c.a.payment.handler.PaymentHandler - \
Payment processed paymentId=pay_44294 userId=usr_28471 amount=22.00 currency=USD \
processor=stripe status=SUCCESS latency_ms=74 traceId=trace-pay05 \
fraudScore=0.01 riskLevel=LOW"""

_PAYMENT_SERVICE_METRICS = """\
Service: payment-service (prod-us-east-1) — PCI DSS compliant zone

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:            650 req/s
    http_request_duration_seconds:
      p50:                          85ms
      p99:                          120ms      (nominal)
    http_requests_errors_total:
      5xx_rate:                     0.005      (nominal — from auth pre-check retries)
    process_cpu_seconds_total:      35.0%
    process_resident_memory_bytes:  1,638 MB / 4,096 MB limit (40.0%)

  TLS Certificate Status:
    payment-gateway.internal:       valid (expires 2024-03-29, 14 days)
    payment-processor.external:     valid (expires 2024-03-29, 14 days)
    auto_renewal:                   scheduled 2024-03-22
    pci_compliance_status:          COMPLIANT"""

_PAYMENT_SERVICE_DEPLOYMENTS = """\
Deployment History: payment-service (prod-us-east-1)

  ┌─ STABLE (current) ───────────────────────────────────────────────────
  │ Version:    v3.9.2
  │ Deployed:   2024-03-04T11:00:00Z (11 days ago)
  │ Triggered:  ci-bot via PR #1901
  │ Commit:     e4f5a6b "PCI compliance audit logging improvements"
  │ CI:         ✓ unit tests | ✓ integration | ✓ PCI scan | ✓ security audit
  │ Image:      registry.internal/payment-service:v3.9.2@sha256:f5a6b7c8...
  │ Status:     STABLE
  └───────────────────────────────────────────────────────────────────────"""

# RED HERRING: search-service elevated cache miss rate
_SEARCH_SERVICE_LOGS = """\
2024-03-15T14:30:00.204Z INFO  [search-svc-d4e5f6] c.a.search.cache.CacheWarmer - \
Cache warm-up initiated after index rebuild (deployed v8.2.1 two days ago) \
indexVersion=idx-20240313 totalEntries=12,000,000 estimatedDuration=45min \
traceId=trace-srch01
2024-03-15T14:30:01.087Z WARN  [search-svc-d4e5f6] c.a.search.cache.CacheWarmer - \
Cache hit rate degraded during warm-up: 95.2% → 78.4% \
reason=index_rebuild_invalidated_cache expectedRecovery=~45min \
traceId=trace-srch01
2024-03-15T14:30:02.498Z INFO  [search-svc-d4e5f6] c.a.search.cache.CacheWarmer - \
Estimated warm-up completion: 2024-03-15T15:15:00Z (populating 12M entries) \
currentProgress=0% populationRate=4,444 entries/sec traceId=trace-srch01
2024-03-15T14:32:00.204Z INFO  [search-svc-e5f6a7] c.a.search.handler.SearchHandler - \
Search completed query="bluetooth headphones" results=142 latency_ms=112 \
cache=MISS index=products-v8 traceId=trace-srch02 userId=anon_44812
2024-03-15T14:32:30.087Z INFO  [search-svc-d4e5f6] c.a.search.handler.SearchHandler - \
Search completed query="usb-c cable" results=89 latency_ms=95 \
cache=MISS index=products-v8 traceId=trace-srch03 userId=anon_28441
2024-03-15T14:33:00.498Z INFO  [search-svc-e5f6a7] c.a.search.handler.SearchHandler - \
Search completed query="mechanical keyboard" results=234 latency_ms=81 \
cache=HIT index=products-v8 traceId=trace-srch04 userId=usr_33918
2024-03-15T14:33:30.204Z INFO  [search-svc-d4e5f6] c.a.search.cache.CacheWarmer - \
Warm-up progress: 34% (4.1M/12M entries populated) elapsed=3m30s \
populationRate=19,523 entries/sec traceId=trace-srch01
2024-03-15T14:34:00.087Z INFO  [search-svc-e5f6a7] c.a.search.handler.SearchHandler - \
Search completed query="wireless mouse" results=167 latency_ms=102 \
cache=MISS index=products-v8 traceId=trace-srch05 userId=anon_71923"""

_SEARCH_SERVICE_METRICS = """\
Service: search-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:            5,400 req/s
    http_request_duration_seconds:
      p50:                          95ms
      p99:                          145ms      (baseline: 120ms — slight elevation during warm-up)
    http_requests_errors_total:
      5xx_rate:                     0.002      (nominal)
    process_cpu_seconds_total:      38.0%
    process_resident_memory_bytes:  1,721 MB / 4,096 MB limit (42.0%)

  Cache Status:
    hit_rate_current:     78.4%     (degraded — warm-up in progress after index rebuild)
    hit_rate_baseline:    95.2%
    warm_up_progress:     34% (4.1M / 12M entries)
    warm_up_eta:          ~30 min
    elasticsearch_health: GREEN (3 nodes, 48 shards)
    auth_required:        false (public search endpoint)"""

# Billing service: healthy but minor cert warning (noise)
_BILLING_SERVICE_LOGS = """\
2024-03-15T14:00:00.204Z INFO  [bill-svc-a1b2c3] c.a.billing.batch.InvoiceGenerator - \
Daily invoice generation batch started batchId=inv-batch-20240315 \
billingCycle=2024-03 traceId=trace-bill01
2024-03-15T14:01:00.087Z INFO  [bill-svc-a1b2c3] c.a.billing.batch.InvoiceGenerator - \
Generated 3,847 invoices for billing cycle 2024-03 \
totalAmount=$284,912.47 currency=USD avgProcessingTime_ms=15 \
traceId=trace-bill01
2024-03-15T14:01:01.498Z INFO  [bill-svc-a1b2c3] c.a.billing.batch.InvoiceGenerator - \
Invoice generation complete, enqueuing to payment-service queue \
queueTopic=billing-invoices messageCount=3847 traceId=trace-bill01
2024-03-15T14:15:00.204Z WARN  [bill-svc-a1b2c3] c.a.billing.tls.CertificateManager - \
Internal CA certificate expires in 30 days (2024-04-14T00:00:00Z) \
issuer=company-internal-ca-v2 renewalTicket=INFRA-8821 \
autoRenewal=scheduled traceId=trace-bill02
2024-03-15T14:32:00.087Z INFO  [bill-svc-d4e5f6] c.a.billing.handler.BillingHandler - \
GET /billing/invoices/usr_28471 status=200 latency_ms=28 \
invoiceCount=3 traceId=trace-bill03
2024-03-15T14:33:00.498Z INFO  [bill-svc-a1b2c3] c.a.billing.handler.BillingHandler - \
GET /billing/usage/usr_33918 status=200 latency_ms=31 \
currentUsage=$127.00 billingCycle=2024-03 traceId=trace-bill04
2024-03-15T14:34:00.204Z INFO  [bill-svc-d4e5f6] c.a.billing.handler.BillingHandler - \
GET /billing/invoices/usr_55301 status=200 latency_ms=25 \
invoiceCount=1 traceId=trace-bill05"""

_BILLING_SERVICE_METRICS = """\
Service: billing-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:            320 req/s
    http_request_duration_seconds:
      p50:                          28ms
      p99:                          55ms       (nominal)
    http_requests_errors_total:
      5xx_rate:                     0.001      (nominal)
    process_cpu_seconds_total:      15.0%
    process_resident_memory_bytes:  901 MB / 4,096 MB limit (22.0%)

  Certificate Status:
    internal_ca_cert:    valid (expires 2024-04-14, 30 days)
    renewal_ticket:      INFRA-8821 (scheduled)"""

# Analytics service: healthy, processing events normally
_ANALYTICS_SERVICE_LOGS = """\
2024-03-15T14:14:45.204Z INFO  [analytics-svc-e5f6a7] c.a.analytics.batch.ReportGenerator - \
Daily report query submitted to database queryId=rpt-daily-20240315 \
expectedRows=10000 expectedDuration=~800ms traceId=trace-anlyt01
2024-03-15T14:14:46.087Z INFO  [analytics-svc-e5f6a7] c.a.analytics.batch.ReportGenerator - \
Report query completed in 852ms (10,241 rows returned — within expected range) \
queryId=rpt-daily-20240315 cacheKey=daily-report-20240315 traceId=trace-anlyt01
2024-03-15T14:14:47.498Z INFO  [analytics-svc-e5f6a7] c.a.analytics.batch.ReportGenerator - \
Report cached and available at /analytics/reports/daily-2024-03-15 \
s3Path=s3://analytics-reports/2024/03/15/daily.parquet \
expiresAt=2024-03-16T14:14:47Z traceId=trace-anlyt01
2024-03-15T14:30:00.204Z INFO  [analytics-svc-f6a7b8] c.a.analytics.ingester.EventIngester - \
Event ingestion rate: 24,500 events/sec (nominal) \
kafkaTopic=analytics-events consumerLag=8 \
partitionsAssigned=16/16 traceId=trace-anlyt02
2024-03-15T14:32:00.087Z INFO  [analytics-svc-f6a7b8] c.a.analytics.ingester.EventIngester - \
Event ingestion rate: 24,800 events/sec (nominal) \
kafkaTopic=analytics-events consumerLag=5 \
batchWriteLatency_ms=12 traceId=trace-anlyt03
2024-03-15T14:34:00.498Z INFO  [analytics-svc-e5f6a7] c.a.analytics.ingester.EventIngester - \
Event ingestion rate: 24,200 events/sec (nominal) \
kafkaTopic=analytics-events consumerLag=11 \
batchWriteLatency_ms=14 traceId=trace-anlyt04"""

_ANALYTICS_SERVICE_METRICS = """\
Service: analytics-service (prod-us-east-1)

  Aggregate Metrics (last 15m, Prometheus):
    http_requests_total:            180 req/s
    http_request_duration_seconds:
      p50:                          18ms
      p99:                          42ms       (nominal)
    http_requests_errors_total:
      5xx_rate:                     0.000
    process_cpu_seconds_total:      22.0%
    process_resident_memory_bytes:  1,434 MB / 4,096 MB limit (35.0%)

  Event Pipeline:
    ingestion_rate:       24,500 events/sec (nominal)
    kafka_consumer_lag:   8 (nominal — threshold: 1000)
    daily_report_status:  COMPLETED (at 14:14Z, 852ms)"""

_USER_SERVICE_LOGS = """\
2024-03-15T14:32:00.204Z INFO  [user-svc-g7h8i9] c.a.user.handler.UserHandler - \
GET /users/usr_28471/profile status=200 latency_ms=42 \
cacheHit=true traceId=trace-usr01 spanId=span-u01
2024-03-15T14:33:00.087Z INFO  [user-svc-j0k1l2] c.a.user.handler.UserHandler - \
GET /users/usr_44192/profile status=200 latency_ms=55 \
cacheHit=false traceId=trace-usr02 spanId=span-u02
2024-03-15T14:34:00.498Z INFO  [user-svc-g7h8i9] c.a.user.handler.UserHandler - \
GET /users/usr_33918/settings status=200 latency_ms=38 \
cacheHit=true traceId=trace-usr03 spanId=span-u03"""

_NOTIFICATION_SERVICE_LOGS = """\
2024-03-15T14:32:00.204Z INFO  [notif-svc-m3n4o5] c.a.notification.sender.EmailSender - \
Email sent to=usr_28471@example.com template=order_confirmation \
smtpLatency_ms=180 provider=ses messageId=msg-n01 traceId=trace-notif01
2024-03-15T14:33:00.087Z WARN  [notif-svc-m3n4o5] c.a.notification.sender.EmailSender - \
Email delivery delayed: SMTP server slow response latency_ms=1200 \
baseline_ms=200 provider=ses target=usr_55301@example.com \
template=shipping_update traceId=trace-notif02
2024-03-15T14:33:01.498Z INFO  [notif-svc-p6q7r8] c.a.notification.sender.EmailSender - \
Email sent to=usr_44192@example.com template=password_reset \
smtpLatency_ms=195 provider=ses messageId=msg-n02 traceId=trace-notif03
2024-03-15T14:34:00.204Z INFO  [notif-svc-m3n4o5] c.a.notification.sender.EmailSender - \
Email sent to=usr_33918@example.com template=order_confirmation \
smtpLatency_ms=172 provider=ses messageId=msg-n03 traceId=trace-notif04"""

_QUEUE_LOGS = """\
2024-03-15T14:32:00.204Z INFO  [kafka-broker-0] c.a.queue.broker.PartitionManager - \
Partition rebalance complete topic=order-events partitions=16 \
consumers=4 strategy=cooperative-sticky rebalanceDuration_ms=847 \
traceId=trace-kafka01
2024-03-15T14:33:00.087Z INFO  [kafka-broker-0] c.a.queue.broker.ConsumerLagMonitor - \
Consumer lag report: topic=order-events \
avgLag=12 maxLag=45 p99Lag=38 consumers=4 partitions=16 \
status=NOMINAL (threshold: maxLag<1000) traceId=trace-kafka02
2024-03-15T14:34:00.498Z INFO  [kafka-broker-0] c.a.queue.broker.ConsumerLagMonitor - \
Consumer lag report: topic=order-events \
avgLag=10 maxLag=38 p99Lag=31 consumers=4 partitions=16 \
status=NOMINAL bytesIn=4.2MB/s bytesOut=4.1MB/s traceId=trace-kafka03"""

_SYSTEM_OVERVIEW = """\
System Overview — prod-us-east-1 — 2024-03-15T14:35:00Z

  Cluster:          prod-us-east-1 (EKS 1.28)
  Namespace:        production
  Total Services:   15
  Services Healthy: 11
  Services Degraded: 3 (api-gateway, auth-service, order-service)
  Services Warning:  1 (recommendation-service — CPU autoscale in progress)
  Services Down:     0

  Active Incidents:
    INC-2024-0315-001: Elevated error rates across multiple services
      Opened:    2024-03-15T14:12:00Z (23 min ago)
      Severity:  SEV-2 (auto-classified by anomaly detector)
      Affected:  ~8% of authenticated requests through api-gateway
      Impact:    Order creation failures, intermittent auth errors
      On-call:   @you (primary), @infra-lead (secondary)
      PagerDuty: incident.pagerduty.com/incidents/P8X2Y4Z
      Slack:     #inc-2024-0315-001

  Recent Activity Timeline:
    14:05Z — config-service pushed rate-limit updates to 4 services (SUCCESS)
    14:10Z — auth-service canary deployment v5.1.0-canary (10% traffic)
    14:12Z — anomaly detector triggered INC-2024-0315-001
    14:14Z — analytics-service daily report query (852ms — expected)
    14:28Z — recommendation-service ML retraining job started (scheduled)
    14:30Z — recommendation-service autoscaler triggered (3→5 replicas)
    14:30Z — search-service cache warm-up started (index rebuild)"""

_SYSTEM_RECENT_CHANGES = """\
Recent Changes (last 24 hours) — prod-us-east-1

  1. [2024-03-15T14:10:00Z] auth-service v5.1.0-canary deployed (10% traffic)
     Type:    Canary deployment
     Change:  Refactored OAuth token validation — claims-validator v3
     Author:  ci-bot (PR #2341 by @sarah-auth, reviewed by @mike-platform)
     Impact:  10% of auth traffic routed to canary pod auth-svc-canary-x9k2m
     Status:  CANARY_ACTIVE (auto-promote blocked — error threshold exceeded)

  2. [2024-03-15T14:05:04Z] config-service rate-limit config push
     Type:    Configuration update (not code deployment)
     Change:  Rate-limit increases: api-gateway 15K→18K, order-service 50→60/user,
              payment-service 30→40/user, auth-service 2.5K→3K
     Author:  @platform-team
     Status:  COMPLETED — all 4 services acknowledged v143

  3. [2024-03-15T12:15:00Z] CDN DNS configuration update
     Type:    Infrastructure change
     Change:  Updated CNAME records for static.example.com
     Author:  @infra-bot (automated)
     Status:  COMPLETED — propagated to all 47 edge nodes

  4. [2024-03-15T06:00:00Z] database maintenance window
     Type:    Automated maintenance
     Change:  Routine VACUUM and index rebuild on auth_sessions, orders tables
     Author:  dba-automation
     Status:  COMPLETED — no anomalies detected

  5. [2024-03-14T22:00:00Z] notification-service config update
     Type:    Configuration update
     Change:  Adjusted email retry backoff 30s→60s
     Author:  @alerts-team
     Status:  COMPLETED

  6. [2024-03-14T16:00:00Z] Kafka partition scaling
     Type:    Infrastructure change
     Change:  Increased partition count 12→16 for order-events topic
     Author:  @platform-team
     Status:  COMPLETED — rebalance finished

  7. [2024-03-13T09:00:00Z] search-service v8.2.1 deployed
     Type:    Rolling deployment
     Change:  Elasticsearch index rebuild, search ranking improvements
     Author:  ci-bot (PR #1892 by @search-team)
     Status:  STABLE (cache warm-up still in progress — 34% complete)"""

_SYSTEM_DEPENDENCY_GRAPH = """\
Service Dependency Graph — prod-us-east-1 (Istio service mesh)

  api-gateway (v3.8.2) — Envoy front-proxy, all external traffic
    ├─→ auth-service (v5.0.4/v5.1.0-canary) [DEGRADED — 8.2% 5xx]
    │     ├─→ database (PostgreSQL 15.4) [HEALTHY — 4ms p50]
    │     ├─→ cache (Redis 7.2) [HEALTHY — 1.1ms p50, 94% hit rate]
    │     ├─→ provider-A (external OAuth) [HEALTHY]
    │     ├─→ provider-B (external OAuth) [HEALTHY]
    │     └─→ provider-C (external OAuth) [HEALTHY]
    ├─→ user-service (v6.1.0) [HEALTHY]
    │     └─→ database [HEALTHY]
    ├─→ payment-service (v3.9.2) [HEALTHY — TLS cert warning, 14 days]
    │     ├─→ database [HEALTHY]
    │     └─→ notification-service (v2.8.1) [HEALTHY]
    │           └─→ queue (Kafka 3.6) [HEALTHY — lag nominal]
    ├─→ order-service (v4.2.1) [DEGRADED — 7.2% 5xx, cascading from auth]
    │     ├─→ auth-service [DEGRADED]
    │     └─→ database [HEALTHY]
    ├─→ search-service (v8.2.1) [HEALTHY — cache warm-up 34%]
    ├─→ billing-service (v1.12.0) [HEALTHY — CA cert warning, 30 days]
    │     └─→ database [HEALTHY]
    └─→ analytics-service (v2.8.0) [HEALTHY]
          └─→ database [HEALTHY]

  recommendation-service (v2.14.0) [WARNING — CPU 92%, autoscaler active]
    └─→ data-lake (S3, async reads)

  config-service (v1.4.2) [HEALTHY — push-based, no runtime dependency]
    └─→ etcd (v3.5.9) — config store

  cdn [HEALTHY — infrastructure-managed, DNS change 2h ago resolved]"""


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

    time_budget = 100
    max_steps = 15
    min_investigations = 4

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

    # Need 3+ for 1.0 score — forces very specific diagnosis
    root_cause_keywords: Set[str] = {
        "canary",
        "provider-b",
        "claims",
        "v5.1.0",
        "nested_permissions",
        "claims-validator",
        "realm_access",
    }

    optimal_actions: List[str] = [
        "rollback auth-service",
        "kill_canary auth-service",
    ]

    initial_alert = (
        "[P2] FIRING: Elevated Error Rates \u2014 Multiple Services\n"
        "Trigger: error_rate_5xx > 0.05 for 5m on api-gateway (current: 0.081)\n"
        "Affected: api-gateway (8.1%), auth-service (8.2%), order-service (7.2%)\n"
        "Also firing: recommendation-service CPU > 90% (autoscaler responding)\n"
        "Note: config-service pushed rate-limit updates to 4 services at 14:10Z\n"
        "Cluster: prod-us-east-1 | Namespace: production\n"
        "Dashboard: https://grafana.internal/d/multi-svc-errors\n"
        "Runbook: https://wiki.internal/runbooks/intermittent-5xx\n"
        "On-call: @you (primary)\n"
        "Started: 2024-03-15T14:12:00Z | Duration: 23m 47s\n"
        "Pattern: Intermittent \u2014 affects ~10% of authenticated requests"
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
                "[P2] FIRING: Elevated error rates across multiple services. "
                "api-gateway 502 at 8.1%. auth-service 5xx at 8.2%. order-service "
                "failures at 7.2%. recommendation-service CPU alert (autoscaler "
                "responding). config-service pushed rate-limit updates at 14:05Z. "
                "Incident started 23m ago. Pattern: intermittent."
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
                "Deployment History: order-service (prod-us-east-1)\n\n"
                "  \u250c\u2500 STABLE (current) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "  \u2502 Version:    v4.2.1\n"
                "  \u2502 Deployed:   2024-03-07T10:00:00Z (8 days ago)\n"
                "  \u2502 Triggered:  ci-bot via PR #2105\n"
                "  \u2502 Commit:     a1b2c3d \"improved order validation error messages\"\n"
                "  \u2502 CI:         \u2713 unit tests | \u2713 integration | \u2713 load test\n"
                "  \u2502 Image:      registry.internal/order-service:v4.2.1@sha256:b2c3d4e5...\n"
                "  \u2502 Status:     STABLE \u2014 no recent changes\n"
                "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            ),
            ("order-service", "dependencies"): (
                "order-service (v4.2.1) \u2014 Dependency Graph\n\n"
                "  Downstream Dependencies:\n"
                "  \u251c\u2500\u2192 auth-service (v5.0.4/v5.1.0-canary) [DEGRADED \u2014 intermittent 500s | circuit: HALF_OPEN]\n"
                "  \u2514\u2500\u2192 database (PostgreSQL 15.4) [HEALTHY \u2014 latency: 4ms | pool: 32/100 | circuit: CLOSED]\n\n"
                "  Upstream Callers:\n"
                "  \u2514\u2500\u2500 api-gateway [routes /api/v2/orders/* to order-service]"
            ),

            # api-gateway -- victim / entry point
            ("api-gateway", "logs"): _API_GATEWAY_LOGS,
            ("api-gateway", "metrics"): _API_GATEWAY_METRICS,
            ("api-gateway", "deployments"): _API_GATEWAY_DEPLOYMENTS,
            ("api-gateway", "dependencies"): (
                "api-gateway (v3.8.2) \u2014 Dependency Graph\n\n"
                "  Upstream: external clients (internet) via ALB / CloudFront\n\n"
                "  Downstream Dependencies (Envoy clusters):\n"
                "  \u251c\u2500\u2192 auth-service      [DEGRADED \u2014 8.2% 5xx | circuit: HALF_OPEN]\n"
                "  \u251c\u2500\u2192 user-service      [HEALTHY  \u2014 0.3% 5xx | circuit: CLOSED]\n"
                "  \u251c\u2500\u2192 payment-service   [HEALTHY  \u2014 0.5% 5xx | circuit: CLOSED]\n"
                "  \u251c\u2500\u2192 order-service     [DEGRADED \u2014 7.2% 5xx | circuit: HALF_OPEN]\n"
                "  \u251c\u2500\u2192 search-service    [HEALTHY  \u2014 0.2% 5xx | circuit: CLOSED]\n"
                "  \u251c\u2500\u2192 billing-service   [HEALTHY  \u2014 0.1% 5xx | circuit: CLOSED]\n"
                "  \u2514\u2500\u2192 analytics-service [HEALTHY  \u2014 0.0% 5xx | circuit: CLOSED]"
            ),

            # user-service -- healthy bystander
            ("user-service", "logs"): _USER_SERVICE_LOGS,
            ("user-service", "metrics"): (
                "Service: user-service (prod-us-east-1)\n\n"
                "  Aggregate Metrics (last 15m, Prometheus):\n"
                "    http_requests_total:           1,800 req/s\n"
                "    http_request_duration_seconds:\n"
                "      p50:                         42ms\n"
                "      p99:                         60ms       (nominal)\n"
                "    http_requests_errors_total:\n"
                "      5xx_rate:                    0.003      (nominal)\n"
                "    process_cpu_seconds_total:     30.0%\n"
                "    process_resident_memory_bytes: 1,434 MB / 4,096 MB limit (35.0%)"
            ),
            ("user-service", "deployments"): (
                "Deployment History: user-service (prod-us-east-1)\n\n"
                "  \u250c\u2500 STABLE (current) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "  \u2502 Version:    v6.1.0\n"
                "  \u2502 Deployed:   2024-03-06T14:00:00Z (9 days ago)\n"
                "  \u2502 Triggered:  ci-bot via PR #2044\n"
                "  \u2502 Commit:     f6a7b8c \"added pagination support for user list endpoint\"\n"
                "  \u2502 CI:         \u2713 unit tests | \u2713 integration\n"
                "  \u2502 Image:      registry.internal/user-service:v6.1.0@sha256:a7b8c9d0...\n"
                "  \u2502 Status:     STABLE\n"
                "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            ),

            # notification-service -- healthy
            ("notification-service", "logs"): _NOTIFICATION_SERVICE_LOGS,
            ("notification-service", "metrics"): (
                "Service: notification-service (prod-us-east-1)\n\n"
                "  Aggregate Metrics (last 15m, Prometheus):\n"
                "    http_requests_total:           420 req/s\n"
                "    http_request_duration_seconds:\n"
                "      p50:                         55ms\n"
                "      p99:                         100ms      (nominal)\n"
                "    http_requests_errors_total:\n"
                "      5xx_rate:                    0.003      (nominal)\n"
                "    process_cpu_seconds_total:     18.0%\n"
                "    process_resident_memory_bytes: 1,024 MB / 4,096 MB limit (25.0%)\n\n"
                "  Email Delivery:\n"
                "    delivery_rate:        99.2%\n"
                "    avg_smtp_latency_ms:  185      (baseline: 180ms)"
            ),

            # database -- healthy but with suspicious slow query
            ("database", "logs"): _DATABASE_LOGS,
            ("database", "metrics"): _DATABASE_METRICS,
            ("database", "deployments"): (
                "Deployment History: database (prod-us-east-1)\n\n"
                "  PostgreSQL 15.4 \u2014 no application-level deployments\n\n"
                "  Infrastructure Events:\n"
                "    2024-03-15T06:00:00Z: Routine maintenance window (VACUUM, index rebuild)\n"
                "    2024-03-10T06:00:00Z: Minor version patch 15.3\u219215.4\n"
                "    2024-03-01T06:00:00Z: Disk volume expansion 500GB\u21921TB\n\n"
                "  Status: STABLE \u2014 no anomalies"
            ),

            # cache -- healthy
            ("cache", "logs"): _CACHE_LOGS,
            ("cache", "metrics"): _CACHE_METRICS,

            # queue -- healthy
            ("queue", "logs"): _QUEUE_LOGS,
            ("queue", "metrics"): (
                "Service: queue (Kafka 3.6, prod-us-east-1)\n\n"
                "  Aggregate Metrics (last 15m, kafka_exporter):\n"
                "    kafka_consumergroup_lag:        avg=12, max=45 (nominal)\n"
                "    kafka_server_brokertopicmetrics:\n"
                "      bytes_in_per_sec:             4.2 MB/s\n"
                "      bytes_out_per_sec:            4.1 MB/s\n"
                "      messages_in_per_sec:          24,500\n"
                "    kafka_topic_partitions:          16 (order-events)\n"
                "    node_cpu_seconds_total:          8.0%\n"
                "    node_memory_MemUsed_bytes:       15.0%\n\n"
                "  Cluster:\n"
                "    brokers: 3/3 healthy\n"
                "    under_replicated_partitions: 0\n"
                "    offline_partitions: 0"
            ),

            # analytics-service -- healthy
            ("analytics-service", "logs"): _ANALYTICS_SERVICE_LOGS,
            ("analytics-service", "metrics"): _ANALYTICS_SERVICE_METRICS,
            ("analytics-service", "deployments"): (
                "Deployment History: analytics-service (prod-us-east-1)\n\n"
                "  \u250c\u2500 STABLE (current) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "  \u2502 Version:    v2.8.0\n"
                "  \u2502 Deployed:   2024-03-02T09:00:00Z (13 days ago)\n"
                "  \u2502 Triggered:  ci-bot via PR #1844\n"
                "  \u2502 Commit:     b8c9d0e \"added daily revenue report aggregation\"\n"
                "  \u2502 CI:         \u2713 unit tests | \u2713 integration | \u2713 data validation\n"
                "  \u2502 Image:      registry.internal/analytics-service:v2.8.0@sha256:c9d0e1f2...\n"
                "  \u2502 Status:     STABLE\n"
                "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            ),

            # billing-service -- healthy with minor cert warning
            ("billing-service", "logs"): _BILLING_SERVICE_LOGS,
            ("billing-service", "metrics"): _BILLING_SERVICE_METRICS,
            ("billing-service", "deployments"): (
                "Deployment History: billing-service (prod-us-east-1)\n\n"
                "  \u250c\u2500 STABLE (current) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "  \u2502 Version:    v1.12.0\n"
                "  \u2502 Deployed:   2024-03-09T15:00:00Z (6 days ago)\n"
                "  \u2502 Triggered:  ci-bot via PR #2156\n"
                "  \u2502 Commit:     d0e1f2a \"invoice template formatting improvements\"\n"
                "  \u2502 CI:         \u2713 unit tests | \u2713 integration | \u2713 financial validation\n"
                "  \u2502 Image:      registry.internal/billing-service:v1.12.0@sha256:e1f2a3b4...\n"
                "  \u2502 Status:     STABLE\n"
                "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
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
                "recommendation-service (v2.14.0) \u2014 Dependency Graph\n\n"
                "  Downstream Dependencies:\n"
                "  \u2514\u2500\u2192 data-lake (S3) [async reads for ML training | status: HEALTHY]\n\n"
                "  Upstream Callers:\n"
                "  \u2514\u2500\u2500 api-gateway [routes /api/v2/recommendations | async, non-blocking]\n\n"
                "  Note: Standalone ML service. No synchronous runtime dependencies.\n"
                "        CPU spike is from scheduled daily retraining job (cron: 0 14 * * *)."
            ),
            ("recommendation-service", "config"): (
                "recommendation-service/config.yaml \u2014 Runtime Configuration\n\n"
                "  ml_pipeline:\n"
                "    model_retraining_schedule: '0 14 * * *'     # daily at 14:00 UTC\n"
                "    model_type: collaborative-filtering-v4\n"
                "    training_data_source: s3://ml-data-lake/interactions/\n"
                "    training_window_days: 7\n"
                "    feature_dimensions: 128\n\n"
                "  autoscaler:\n"
                "    enabled: true\n"
                "    min_replicas: 3\n"
                "    max_replicas: 8\n"
                "    target_cpu: 70\n"
                "    scale_up_cooldown: 60s\n"
                "    scale_down_cooldown: 300s\n"
                "    current_replicas: 5 (scaled at 14:30Z \u2014 expected during retraining)"
            ),

            # cdn: DNS change 2 hours ago
            ("cdn", "logs"): _CDN_LOGS,
            ("cdn", "metrics"): (
                "Service: cdn (CloudFront, 47 edge locations)\n\n"
                "  Aggregate Metrics (last 15m):\n"
                "    avg_latency_ms:            19\n"
                "    error_rate:                0.001      (nominal)\n"
                "    cache_hit_rate_pct:        98.7%\n"
                "    bandwidth_utilization_pct: 34.2%\n"
                "    node_cpu_seconds_total:    5.0%\n"
                "    node_memory_pct:           10.0%\n\n"
                "  DNS:\n"
                "    last_config_change:   2024-03-15T12:15:00Z (2 hours ago)\n"
                "    change_type:          CNAME update for static.example.com\n"
                "    propagation_status:   COMPLETE (all 47 edge nodes)\n"
                "    post_change_health:   PASSED"
            ),
            ("cdn", "deployments"): (
                "Deployment History: cdn\n\n"
                "  Infrastructure-managed \u2014 no application deployments.\n\n"
                "  Recent Infrastructure Events:\n"
                "    2024-03-15T12:15:00Z: DNS CNAME update for static.example.com\n"
                "                          Propagation: COMPLETE (5 min)\n"
                "                          Post-change health: PASSED\n"
                "    2024-03-01T08:00:00Z: Edge node capacity expansion (+12 locations)"
            ),

            # config-service: pushed rate-limit updates recently
            ("config-service", "logs"): _CONFIG_SERVICE_LOGS,
            ("config-service", "metrics"): _CONFIG_SERVICE_METRICS,
            ("config-service", "deployments"): _CONFIG_SERVICE_DEPLOYMENTS,
            ("config-service", "dependencies"): (
                "config-service (v1.4.2) \u2014 Dependency Graph\n\n"
                "  Downstream Dependencies:\n"
                "  \u2514\u2500\u2192 etcd (v3.5.9) [HEALTHY \u2014 3/3 members | leader: etcd-0]\n\n"
                "  Push Targets (fire-and-forget with ack):\n"
                "  \u251c\u2500\u2192 api-gateway       [last push: 14:05Z | ack: OK]\n"
                "  \u251c\u2500\u2192 order-service     [last push: 14:05Z | ack: OK]\n"
                "  \u251c\u2500\u2192 payment-service   [last push: 14:05Z | ack: OK]\n"
                "  \u2514\u2500\u2192 auth-service      [last push: 14:05Z | ack: OK]\n\n"
                "  Note: Push-based service. No runtime dependency from other services."
            ),
            ("config-service", "config"): (
                "config-service/config.yaml \u2014 Runtime Configuration\n\n"
                "  push_engine:\n"
                "    mode: fire-and-forget with ack\n"
                "    push_timeout_sec: 10\n"
                "    rollback_on_failure: false\n"
                "    max_concurrent_pushes: 4\n\n"
                "  audit:\n"
                "    enabled: true\n"
                "    s3_bucket: s3://audit-logs/config/\n"
                "    retention_days: 90\n\n"
                "  storage:\n"
                "    backend: etcd (v3.5.9)\n"
                "    cluster: etcd-0, etcd-1, etcd-2\n"
                "    health: HEALTHY"
            ),

            # payment-service: cert renewal warning
            ("payment-service", "logs"): _PAYMENT_SERVICE_LOGS,
            ("payment-service", "metrics"): _PAYMENT_SERVICE_METRICS,
            ("payment-service", "deployments"): _PAYMENT_SERVICE_DEPLOYMENTS,
            ("payment-service", "dependencies"): (
                "payment-service (v3.9.2) \u2014 Dependency Graph\n\n"
                "  Downstream Dependencies:\n"
                "  \u251c\u2500\u2192 database (PostgreSQL 15.4) [HEALTHY \u2014 latency: 5ms | pool: 28/100 | circuit: CLOSED]\n"
                "  \u251c\u2500\u2192 notification-service (v2.8.1) [HEALTHY \u2014 latency: 55ms | circuit: CLOSED]\n"
                "  \u2514\u2500\u2192 auth-service (pre-check) [DEGRADED \u2014 intermittent 500s on token validation]\n\n"
                "  Upstream Callers:\n"
                "  \u251c\u2500\u2500 api-gateway [routes /api/v2/payments]\n"
                "  \u2514\u2500\u2500 order-service [payment processing after order creation]\n\n"
                "  External:\n"
                "  \u2514\u2500\u2192 stripe (payment processor) [HEALTHY \u2014 mTLS | cert expires 2024-03-29]"
            ),
            ("payment-service", "config"): (
                "payment-service/config.yaml \u2014 Runtime Configuration (PCI DSS zone)\n\n"
                "  tls:\n"
                "    cert_path: /etc/ssl/payment-gateway.pem\n"
                "    cert_expiry: 2024-03-29T00:00:00Z (14 days)\n"
                "    mtls_enabled: true\n"
                "    auto_renewal: scheduled 2024-03-22\n"
                "    processor: stripe\n\n"
                "  auth_pre_check:\n"
                "    enabled: true        # validates user token before processing payment\n"
                "    upstream: auth-service\n"
                "    retry_policy: exponential_backoff (3 attempts)\n"
                "    timeout_ms: 2000\n\n"
                "  compliance:\n"
                "    pci_mode: strict\n"
                "    audit_logging: enabled\n"
                "    encryption_at_rest: AES-256-GCM"
            ),

            # search-service: cache miss rate elevated
            ("search-service", "logs"): _SEARCH_SERVICE_LOGS,
            ("search-service", "metrics"): _SEARCH_SERVICE_METRICS,
            ("search-service", "deployments"): (
                "Deployment History: search-service (prod-us-east-1)\n\n"
                "  \u250c\u2500 STABLE (current) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "  \u2502 Version:    v8.2.1\n"
                "  \u2502 Deployed:   2024-03-13T09:00:00Z (2 days ago)\n"
                "  \u2502 Triggered:  ci-bot via PR #1892\n"
                "  \u2502 Commit:     e2f3a4b \"Elasticsearch index rebuild, search ranking improvements\"\n"
                "  \u2502 CI:         \u2713 unit tests | \u2713 integration | \u2713 relevance benchmarks\n"
                "  \u2502 Image:      registry.internal/search-service:v8.2.1@sha256:f3a4b5c6...\n"
                "  \u2502 Status:     STABLE (cache warm-up in progress \u2014 34% complete)\n"
                "  \u2502 Note:       Cache hit rate temporarily degraded (78.4% vs 95.2% baseline)\n"
                "  \u2502             Expected full recovery in ~30 min\n"
                "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            ),
            ("search-service", "config"): (
                "search-service/config.yaml \u2014 Runtime Configuration\n\n"
                "  elasticsearch:\n"
                "    version: 8.12.0\n"
                "    cluster_health: GREEN\n"
                "    nodes: 3\n"
                "    shards: 48 (all assigned)\n"
                "    index: products-v8\n\n"
                "  cache:\n"
                "    total_entries: 12,000,000\n"
                "    ttl_sec: 3600\n"
                "    warm_up_status: IN_PROGRESS (34% complete)\n"
                "    warm_up_eta: ~30 min\n"
                "    eviction_policy: LRU\n\n"
                "  auth:\n"
                "    required: false       # public search endpoint, no auth dependency"
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
        # Only the direct root-cause investigations count as relevant.
        # Investigating order-service or api-gateway gives useful context
        # but doesn't count toward efficiency — they're symptoms.
        return {
            ("auth-service", "logs"),
            ("auth-service", "metrics"),
            ("auth-service", "deployments"),
            ("auth-service", "config"),
            ("system", "recent_changes"),
        }
