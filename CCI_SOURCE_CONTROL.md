<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# CCI source configuration control (protocol 1)

Companion implementation for [CCI PR #2603](https://github.com/CCI-58/cci/pull/2603).
This is a fork extension; stock Apache beta8/beta18 do not provide this protocol.
The implementation is under review and has not been deployed or verified against
a running CCI/DevLake pair.

## Contract

The existing API authentication remains required. Control endpoints additionally
require `X-CCI-Control-Key`, equal to the deployment environment variable
`CCI_SOURCE_CONTROL_KEY` (at least 32 bytes). Keep this credential in the secret
store, outside API-editable configuration. Do not put it in URLs or application logs.

| Request | Result |
| --- | --- |
| `POST /cci/source-control` with `{"operation":"<revision UUID>","blueprints":[1,2]}` | Acquire or recover the same operation and protected set |
| `GET /cci/source-control/<revision UUID>` | Verify ownership |
| `DELETE /cci/source-control/<revision UUID>` | Explicit successful completion; same-operation retry is idempotent |

Acquire and check return `protocol: 1`, `operation`, sorted `blueprints`, and
`held: true`. UUIDs use lower-case canonical notation. Blueprint IDs must be
positive, unique, and at most 1,000 per request. An empty set supports webhook-only
changes. A different operation or different protected set cannot replace a held fence.

While held, normal HTTP mutations are refused (409), including the GET migration
confirmation endpoint. Owner mutations carry `X-CCI-Source-Token`, the lower-case
hex HMAC-SHA256 of `cci-source-control-v1:<revision UUID>` using the control key.
Provided owner tokens are rejected after release, including delayed requests.
Read requests remain available. Webhook HTTP writes are also paused and require
the sender's retry/queue handling; this implementation conservatively fences all
HTTP mutations on the instance, not just configuration endpoints.

Acquisition drains in-flight HTTP mutations and pipeline admission before storing
the fence. New scheduled pipelines and reruns for protected blueprints are
refused; unattributed manual plans are also refused. Independent scheduled
blueprints remain eligible. Previously admitted pipelines continue draining so
CCI can await completion. Scheduled jobs reload the blueprint under admission,
so captured pre-change configuration cannot be used after release.

## Persistence and recovery

The singleton `_devlake_cci_source_control` table is bootstrapped after the existing
`lockDatabase()` process exclusion and before API/scheduler startup, like the
existing locking metadata. This design relies on DevLake's existing guarantee of
one backend process per database. It is not a multi-writer database protocol.
Missing/corrupt state or a database error refuses writes and admission.

There is no expiry and no release on request completion, CCI failure, or restart.
CCI retries the same immutable revision, finishes apply/adoption/restoration,
persists FINALIZING, explicitly releases, and then persists ACTIVE. Losing the
release response leaves FINALIZING retryable by the same revision; it does not
report a completed change. Removing the secret does not remove protection.
Do not remove this row or disable the fence to recover an incomplete operation.

## Rollout and verification remaining

Build a fork backend image tied to a reviewed commit and use an immutable digest.
Provision the matching secret to CCI and DevLake, stop the stock backend before
starting the replacement, retain the same database, and verify protocol 1 before
enabling CCI application. Keep rollback images and database backup available.
Do not run a stock/older backend against a database with an incomplete controlled
operation: it does not enforce this fence. Do not combine an unfinished operation
with an unrelated schema upgrade. No deployment or data reset is part of this PR.

Local validation: `go test -race ./helpers/sourcecontrol ./server/api` with the
source-control test filter, and
`go build ./server/services ./server/api` passed. The service package test command
requires the repository's generated mocks (`make mock`); its first local attempt
stopped because those mocks were absent, not because assertions passed.
Broad repository tests belong to CI. Before enabling application, jointly verify
real database persistence across backend restart, protected cron/manual admission,
already-admitted draining, webhook retry, owner updates, failed release/retry,
and the CCI saved-result read gates. These integration checks remain outstanding.
