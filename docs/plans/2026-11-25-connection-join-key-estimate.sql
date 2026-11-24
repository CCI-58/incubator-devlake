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

-- Read-only MySQL estimate; see companion plan for scope and interpretation.
SET SESSION MAX_EXECUTION_TIME=30000;
START TRANSACTION READ ONLY;
SELECT 'pr_commit' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_pull_request_commits c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_request_id GROUP BY p.connection_id, p.repo_id, c.pull_request_id, c.commit_sha) k;
SELECT 'pr_issue' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_pull_request_issues c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_request_id GROUP BY p.connection_id, p.repo_id, c.pull_request_id, c.issue_id) k;
SELECT 'pr_label' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_pull_request_labels c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_id GROUP BY p.connection_id, p.repo_id, c.pull_id, c.label_name) k;
SELECT 'pr_comment' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_pull_request_comments c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_request_id GROUP BY p.connection_id, p.repo_id, c.github_id) k;
SELECT 'pr_review' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_pull_request_reviews c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_request_id GROUP BY p.connection_id, p.repo_id, c.github_id) k;
SELECT 'review' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_reviewers c JOIN _tool_github_pull_requests p ON p.github_id=c.pull_request_id GROUP BY p.connection_id, p.repo_id, c.pull_request_id, c.reviewer_id) k;
SELECT 'issue_comment' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_issue_comments c JOIN _tool_github_issues p ON p.github_id=c.issue_id GROUP BY p.connection_id, p.repo_id, c.github_id) k;
SELECT 'issue_label' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_issue_labels c JOIN _tool_github_issues p ON p.github_id=c.issue_id GROUP BY p.connection_id, p.repo_id, c.issue_id, c.label_name) k;
SELECT 'milestone_issue' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_github_issues c JOIN _tool_github_milestones p ON p.milestone_id=c.milestone_id GROUP BY p.connection_id, p.repo_id, p.milestone_id, c.github_id) k;
SELECT 'sonar_code_block' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_sonarqube_issue_code_blocks c JOIN _tool_sonarqube_issues p ON p.issue_key=c.issue_key GROUP BY c.connection_id, p.project_key, c.id) k;
SELECT 'jenkins_stage' AS converter, COUNT(*) AS old_keys, COALESCE(SUM(same_connection),0) AS corrected_keys, COALESCE(SUM(1-same_connection),0) AS removed_keys FROM (SELECT MAX(CASE WHEN c.connection_id=p.connection_id THEN 1 ELSE 0 END) AS same_connection FROM _tool_jenkins_stages c JOIN _tool_jenkins_builds p ON p.full_name=c.build_name GROUP BY p.connection_id, p.job_path, p.job_name, c.build_name, c.id) k;
COMMIT;
