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
