/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"github.com/apache/incubator-devlake/core/models/domainlayer/code"
	"github.com/apache/incubator-devlake/core/models/domainlayer/crossdomain"
	"github.com/apache/incubator-devlake/core/models/domainlayer/ticket"
	"github.com/apache/incubator-devlake/helpers/e2ehelper"
	"github.com/apache/incubator-devlake/plugins/github/impl"
	"github.com/apache/incubator-devlake/plugins/github/models"
	"github.com/apache/incubator-devlake/plugins/github/tasks"
	"gorm.io/gorm/schema"
	"testing"
)

func TestGithubConnectionIsolation(t *testing.T) {

	t.Run("pr_commits", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_pr_commits.csv", models.GithubPrCommit{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubPrCommit{}, models.GithubPullRequest{}, tasks.PullRequestCommitsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertPullRequestCommitsMeta, data) }, map[schema.Tabler]int64{code.PullRequestCommit{}: 2})
	})

	t.Run("pr_issues", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_pr_issues.csv", models.GithubPrIssue{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubPrIssue{}, models.GithubPullRequest{}, tasks.PullRequestIssuesClauses(1, 100),
			func() { d.Subtask(tasks.ConvertPullRequestIssuesMeta, data) }, map[schema.Tabler]int64{crossdomain.PullRequestIssue{}: 2})
	})

	t.Run("pr_labels", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_pr_labels.csv", models.GithubPrLabel{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubPrLabel{}, models.GithubPullRequest{}, tasks.PullRequestLabelsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertPullRequestLabelsMeta, data) }, map[schema.Tabler]int64{code.PullRequestLabel{}: 2})
	})

	t.Run("pr_comments", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_pr_comments.csv", models.GithubPrComment{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubPrComment{}, models.GithubPullRequest{}, tasks.PullRequestCommentsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertPullRequestCommentsMeta, data) }, map[schema.Tabler]int64{code.PullRequestComment{}: 2})
	})

	t.Run("pr_reviews", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_pr_reviews.csv", models.GithubPrReview{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubPrReview{}, models.GithubPullRequest{}, tasks.PullRequestReviewsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertPullRequestReviewsMeta, data) }, map[schema.Tabler]int64{code.PullRequestComment{}: 2})
	})

	t.Run("reviews", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_prs.csv", models.GithubPullRequest{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_reviews.csv", models.GithubReviewer{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubReviewer{}, models.GithubPullRequest{}, tasks.ReviewsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertReviewsMeta, data) }, map[schema.Tabler]int64{code.PullRequestReviewer{}: 2})
	})

	t.Run("issue_comments", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_issues.csv", models.GithubIssue{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_issue_comments.csv", models.GithubIssueComment{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubIssueComment{}, models.GithubIssue{}, tasks.IssueCommentsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertIssueCommentsMeta, data) }, map[schema.Tabler]int64{ticket.IssueComment{}: 2})
	})

	t.Run("issue_labels", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_issues.csv", models.GithubIssue{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_issue_labels.csv", models.GithubIssueLabel{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubIssueLabel{}, models.GithubIssue{}, tasks.IssueLabelsClauses(1, 100),
			func() { d.Subtask(tasks.ConvertIssueLabelsMeta, data) }, map[schema.Tabler]int64{ticket.IssueLabel{}: 2})
	})

	t.Run("milestones", func(t *testing.T) {
		d := e2ehelper.NewDataFlowTester(t, "github", impl.Github{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_milestones.csv", models.GithubMilestone{})
		d.ImportCsvIntoTabler("./raw_tables/connection_isolation_milestone_issues.csv", models.GithubIssue{})
		data := &tasks.GithubTaskData{Options: &tasks.GithubOptions{ConnectionId: 1, GithubId: 100, Name: "test/repo"}}
		e2ehelper.VerifyConnectionIsolation(d, models.GithubIssue{}, models.GithubMilestone{}, tasks.MilestonesClauses(1, 100),
			func() { d.Subtask(tasks.ConvertMilestonesMeta, data) }, map[schema.Tabler]int64{ticket.Sprint{}: 1, ticket.BoardSprint{}: 1, ticket.SprintIssue{}: 2})
	})
}
