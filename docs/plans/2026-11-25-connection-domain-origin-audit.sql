/*
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
*/

-- MySQL 8, read-only. No raw params, entity IDs or payloads are returned.
-- Audits all stored scopes matching these model prefixes, including inactive scopes.
-- A zero mismatch count is insufficient: invalid/unparsed values require inspection.
-- IDs without a recognized model prefix and unrelated models are OUTSIDE this query.
-- Also reconcile old-only keys and inventory unattributed raw rows as described in the plan.
SET SESSION MAX_EXECUTION_TIME=30000;
START TRANSACTION READ ONLY;
WITH identities AS (
SELECT 'pull_request_commits/github:GithubPullRequest' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_commits WHERE pull_request_id LIKE 'github:GithubPullRequest:%'
UNION ALL
SELECT 'pull_request_issues/github:GithubPullRequest' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN issue_id REGEXP '^github:GithubIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_issues WHERE pull_request_id LIKE 'github:GithubPullRequest:%'
UNION ALL
SELECT 'pull_request_labels/github:GithubPullRequest' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_labels WHERE pull_request_id LIKE 'github:GithubPullRequest:%'
UNION ALL
SELECT 'pull_request_comments/github:GithubPrComment' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^github:GithubPrComment:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_comments WHERE id LIKE 'github:GithubPrComment:%'
UNION ALL
SELECT 'pull_request_comments/github:GithubPrReview' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^github:GithubPrReview:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_comments WHERE id LIKE 'github:GithubPrReview:%'
UNION ALL
SELECT 'pull_request_reviewers/github:GithubPullRequest' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN pull_request_id REGEXP '^github:GithubPullRequest:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pull_request_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN reviewer_id REGEXP '^github:GithubAccount:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(reviewer_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM pull_request_reviewers WHERE pull_request_id LIKE 'github:GithubPullRequest:%'
UNION ALL
SELECT 'issue_comments/github:GithubIssueComment' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^github:GithubIssueComment:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN issue_id REGEXP '^github:GithubIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM issue_comments WHERE id LIKE 'github:GithubIssueComment:%'
UNION ALL
SELECT 'issue_labels/github:GithubIssue' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN issue_id REGEXP '^github:GithubIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN issue_id REGEXP '^github:GithubIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM issue_labels WHERE issue_id LIKE 'github:GithubIssue:%'
UNION ALL
SELECT 'sprints/github:GithubMilestone' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^github:GithubMilestone:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN original_board_id REGEXP '^github:GithubRepo:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(original_board_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM sprints WHERE id LIKE 'github:GithubMilestone:%'
UNION ALL
SELECT 'board_sprints/github:GithubMilestone' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN sprint_id REGEXP '^github:GithubMilestone:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(sprint_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN board_id REGEXP '^github:GithubRepo:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(board_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM board_sprints WHERE sprint_id LIKE 'github:GithubMilestone:%'
UNION ALL
SELECT 'sprint_issues/github:GithubMilestone' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN sprint_id REGEXP '^github:GithubMilestone:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(sprint_id, ':', 3), ':', -1) END AS id_connection, CASE WHEN issue_id REGEXP '^github:GithubIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM sprint_issues WHERE sprint_id LIKE 'github:GithubMilestone:%'
UNION ALL
SELECT 'cq_issue_code_blocks/sonarqube:SonarqubeIssueCodeBlock' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^sonarqube:SonarqubeIssueCodeBlock:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN issue_key REGEXP '^sonarqube:SonarqubeIssue:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(issue_key, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.connectionId')) END AS params_connection FROM cq_issue_code_blocks WHERE id LIKE 'sonarqube:SonarqubeIssueCodeBlock:%'
UNION ALL
SELECT 'cicd_tasks/jenkins:JenkinsStage' AS audit_scope, _raw_data_table AS raw_table, CASE WHEN id REGEXP '^jenkins:JenkinsStage:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(id, ':', 3), ':', -1) END AS id_connection, CASE WHEN pipeline_id REGEXP '^jenkins:JenkinsBuild:[1-9][0-9]*:.+$' THEN SUBSTRING_INDEX(SUBSTRING_INDEX(pipeline_id, ':', 3), ':', -1) END AS related_connection, CASE WHEN JSON_VALID(_raw_data_params) THEN JSON_UNQUOTE(JSON_EXTRACT(_raw_data_params, '$.ConnectionId')) END AS params_connection FROM cicd_tasks WHERE id LIKE 'jenkins:JenkinsStage:%'
), classified AS (
 SELECT *, CASE
   WHEN id_connection IS NULL OR related_connection IS NULL THEN 'invalid_domain_id'
   WHEN params_connection IS NULL OR params_connection NOT REGEXP '^[1-9][0-9]*$' THEN 'invalid_or_missing_params_connection'
   WHEN id_connection <> related_connection THEN 'related_id_connection_mismatch'
   WHEN id_connection <> params_connection THEN 'origin_connection_mismatch'
   ELSE 'connection_matches'
 END AS audit_result
 FROM identities
)
SELECT audit_scope, raw_table, id_connection, params_connection, audit_result, COUNT(*) AS row_count
FROM classified
GROUP BY audit_scope, raw_table, id_connection, params_connection, audit_result
ORDER BY audit_scope, raw_table, id_connection, params_connection, audit_result;
COMMIT;
