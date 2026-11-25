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
	"github.com/apache/incubator-devlake/core/models/domainlayer/codequality"
	"github.com/apache/incubator-devlake/helpers/e2ehelper"
	"github.com/apache/incubator-devlake/plugins/sonarqube/impl"
	"github.com/apache/incubator-devlake/plugins/sonarqube/models"
	"github.com/apache/incubator-devlake/plugins/sonarqube/tasks"
	"gorm.io/gorm/schema"
	"testing"
)

func TestSonarqubeConnectionIsolation(t *testing.T) {
	d := e2ehelper.NewDataFlowTester(t, "sonarqube", impl.Sonarqube{})
	d.ImportCsvIntoTabler("./raw_tables/connection_isolation_issues.csv", models.SonarqubeIssue{})
	d.ImportCsvIntoTabler("./raw_tables/connection_isolation_blocks.csv", models.SonarqubeIssueCodeBlock{})
	data := &tasks.SonarqubeTaskData{Options: &tasks.SonarqubeOptions{ConnectionId: 1, ProjectKey: "project"}}
	e2ehelper.VerifyConnectionIsolation(d, models.SonarqubeIssueCodeBlock{}, models.SonarqubeIssue{}, tasks.IssueCodeBlocksClauses(1, "project"),
		func() { d.Subtask(tasks.ConvertIssueCodeBlocksMeta, data) }, map[schema.Tabler]int64{codequality.CqIssueCodeBlock{}: 2})
}
