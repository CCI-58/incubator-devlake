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

## Existing beta8 deployment baseline

The deployment inspected on 2026-10-03 reports `v1.0.3-beta8@cfe519c`.
The first CCI image was built from the older fork main and lacked beta8's
Bitbucket API-token support and Argo CD image-support migration/implementation.
The live database already records `argocd add image support artifacts`
(`20251102160000`), even though current Bitbucket/Argo CD connection counts are
zero. Do not deploy that older image on the assumption that it is beta8 plus
the CCI extension.

This branch merges the official `v1.0.3-beta8` commit
`cfe519cf9bb02eeec8e918024810b479c8be231d`, preserving the CCI persistent fence,
SonarQube error handling, and image publication workflow. Existing core/plugin
migration scripts now match beta8. The control table remains an additional
startup AutoMigrate. This is baseline alignment, not an upgrade to beta18.
Publish a new image after review and update GitOps from its successful main-run
artifact. Existing-database restore/startup and CCI integration remain required;
fresh-database smoke alone is not that evidence.

Merge this PR using **Create a merge commit**, not squash or rebase. Keep the
official beta8 commit in the ancestry so future upstream merges use the correct
merge base. After merging, verify:

```sh
git merge-base --is-ancestor cfe519cf9bb02eeec8e918024810b479c8be231d origin/main
```

The published `/version` is `v1.0.3-beta8-cci@<full fork SHA>`. The image smoke test
checks this exact value. CCI must explicitly support this fork version after
compatibility verification; the prefix is not proof that a stock beta8 image
supports the control API. CCI's version gate remains a separate deployment task.

## Contract

### Image publication and GitOps handoff

`.github/workflows/cci-image.yml` builds the complete backend for linux/amd64,
runs source-control tests and starts the actual image on disposable MySQL. The
smoke test checks the source SHA, authentication, fence persistence across a
backend restart, and explicit release. PR builds never publish. Successful main
builds push that same tested image to `ccicontainer.azurecr.io/devlake-cci` and
archive `image-release.json` with its immutable registry digest and workflow URL.
This smoke test does not replace migration/restore or CCI integration testing.

The fork repository needs `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
`AZURE_SUBSCRIPTION_ID` Actions secrets and Azure OIDC federation restricted to
`repo:CCI-58/incubator-devlake:ref:refs/heads/main`, with ACR push permission.
Updating a personal GitHub PAT does not configure these credentials.
The legacy DockerHub publication workflows are disabled in this fork.

GitOps consumes the release artifact after verifying the successful main run.
Only the test tenant is prepared initially; registry pull credentials and the
shared control Secret must exist before rollout. Keep one backend replica and
Recreate strategy. The image identifies itself by fork SHA, not as official
beta18. Publication, GitOps promotion and actual CCI compatibility remain separate
gates. No image has been published or deployed by this implementation work yet.

### API authentication

Existing `/rest` API authentication remains in force when using that routing path;
direct internal routes do not enforce that bearer authentication. Control endpoints always
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

## Durable cancellation (cancellation capability 1)

`GET /cci/source-control/capabilities` requires the control credential and a ready backend,
and returns `{"protocol":1,"cancellation":1}`. Existing protocol 1 acquire/check/release remain compatible.
`POST /cci/source-control/{operation}/cancel` permanently records the UUID and releases its fence if held.
It returns `{"protocol":1,"operation":"<uuid>","cancelled":true}`. Repeating it is safe, including when
another operation now holds the fence: that other operation is not released. A never-acquired UUID can
be cancelled so a delayed acquire cannot take effect later.

CCI must serialize cancellation against creating its operation record and only cancel STARTING operations
before external configuration writes. The deployment credential can cancel any UUID, so this precondition
is enforced by the trusted CCI caller, not inferred from DevLake pipeline state.

Cancellation UUIDs are retained in `_devlake_cci_source_control_cancellations` with no expiry. The row is
persisted before releasing the singleton fence. If release fails, cancellation can be retried after restart;
acquire remains rejected. Do not truncate either control metadata table during maintenance. Both are
initialized after the existing database process lock. The CI image smoke checks cancellation across restart
against actual MySQL; race tests cover cancellation versus a delayed acquisition.

Control credentials require TLS on the CCI-to-DevLake route. This change does not deploy an image or alter
GitOps. Publish the tested merge image, audit its exact SHA/digest, validate TLS routing and update CCI's
explicit version gate before enabling the CCI runner.

## HTTP quiescence and resolution receipts (capability `quiescence: 1`)

This extension supplies an HTTP admission barrier for C59-1016. It is **not** a
certificate that external connection data has been reconciled, a database commit
has settled, or a running collection pipeline has stopped. Do not release the
CCI operation reservation based on this receipt alone.

The authenticated capabilities response advertises `quiescence: 1` only when the
store implements the durable resolution journal. Stock images and older builds
must be rejected by clients. Pin the approved full `/version` value as well as
checking the capability; never derive the expected version from the remote reply.

| Request | Result |
| --- | --- |
| `POST /cci/source-control/<operation>/quiesce` with `{"evidence":"<UUID>","blueprints":[1,2]}` | Drain admitted mutating HTTP handlers, revoke old admission, hold the protected fence and persist QUIESCED |
| `GET /cci/source-control/<operation>/resolutions/<evidence>` | Read the matching receipt without acquiring or releasing anything |
| `POST /cci/source-control/<operation>/resolutions/<evidence>/release` | After caller-side reconciliation, drain cleanup handlers, persist release intent, release only this fence, persist RELEASED |

All endpoints require the existing deployment control key. They return
`protocol: 1`, `quiescence: 1`, `operation`, `evidence`, canonical `blueprints`, and
`phase` (QUIESCED, RELEASING, RELEASED). Operation/evidence/protected set are
immutable for a journal entry. Reusing an operation with another proof is rejected.

The quiescence handler takes the exclusive write lock, which waits for all
already admitted mutating handlers. It persists the existing cancellation
tombstone before saving a fence/receipt. Delayed acquisitions and old source
tokens are permanently rejected, including after restart and after a failed
fence save. A failure before the receipt exists requires another quiescence
attempt; it is never reported as a completed barrier. A different active owner
is never displaced. Recovering an unheld fence creates **new** cleanup ownership
and does not attest to continuity of the original operation.

Cleanup uses `X-CCI-Resolution-Token`:
`hex(HMAC-SHA256(controlKey, "cci-source-resolution-v1:" + operation + ":" + evidence))`.
It is separate from the old source token. Requests supplying both tokens are
rejected. The cleanup token works only while that journal is QUIESCED and its
fence is held; ordinary writes and protected pipeline admissions remain blocked.
Normal release/cancel endpoints cannot bypass an existing journal. This token
permits mutating handlers; the CCI reconciliation adapter must still restrict
which operations it performs and must not blindly resend a historical create.
Existing authentication behavior on direct/internal versus `/rest` routes is
unchanged.

RELEASING is persisted before clearing the held flag. If the final receipt save
fails, a retry can finish the historical receipt even after a different operation
has acquired the singleton; it never clears the new owner's fence. RELEASED
receipts and cancellation tombstones are retained after later operations and
restart. The new journal is bootstrapped with the existing runtime control tables,
without clearing existing control rows; data-reset test helpers preserve it.

### Remaining integration requirements

- Verify the current external identity/ownership and CCI save state for both
  REQUESTED and APPLIED. The CCI ledger's APPLIED-lost-fence exit is still pending.
- Resolve uncertain database writes before considering a snapshot stable. A
  returned HTTP handler can have observed a database transport error without
  proving that an already accepted SQL statement cannot commit later. This
  barrier also does not drain existing asynchronous collection work. Database
  transaction evidence or a separately verified maintenance procedure is needed
  for those cases; a timeout or missing list entry is not such evidence.
- Enforce actor/project authorization and associate the receipt with the pinned
  target and immutable operation input. Verify cleanup and CCI consistency before
  calling release. A UUID entered in a UI is not proof of reconciliation.
- Integrate the CCI resolver/UI, then run the real CCI/image/database acceptance
  scenarios before enabling the feature. This implementation performs no rollout.

### Verification

Race-enabled helper/API tests exercise handler draining, revoked old tokens,
restart, proof mismatch, other-owner rejection, cleanup draining, and failure at
fence/journal/release-intent/final-receipt persistence. An isolated MySQL test uses
the production store to verify durable receipts and cancellation, immutable
proofs, and release retries after a subsequent owner. CCI and Go share a fixed
HMAC protocol vector. CI runs these before the existing complete image build.
The MySQL store test is compiled with its production source file to avoid the
unrelated services tests' generated-mock prerequisite. Full image startup and
CCI-to-image integration are separate checks; they have not run locally here.
