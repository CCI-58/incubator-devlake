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
	"github.com/apache/incubator-devlake/core/models/domainlayer/devops"
	"github.com/apache/incubator-devlake/helpers/e2ehelper"
	"github.com/apache/incubator-devlake/helpers/pluginhelper/api"
	"github.com/apache/incubator-devlake/plugins/jenkins/impl"
	"github.com/apache/incubator-devlake/plugins/jenkins/models"
	"github.com/apache/incubator-devlake/plugins/jenkins/tasks"
	"gorm.io/gorm/schema"
	"testing"
)

func TestJenkinsStageConnectionIsolation(t *testing.T) {
	for _, class := range []string{"", tasks.WORKFLOW_MULTI_BRANCH_PROJECT} {
		t.Run("class="+class, func(t *testing.T) {
			d := e2ehelper.NewDataFlowTester(t, "jenkins", impl.Jenkins{})
			d.ImportCsvIntoTabler("./raw_tables/connection_isolation_builds.csv", models.JenkinsBuild{})
			d.ImportCsvIntoTabler("./raw_tables/connection_isolation_stages.csv", models.JenkinsStage{})
			options := &tasks.JenkinsOptions{ConnectionId: 1, JobName: "job", JobPath: "path/", JobFullName: "job", Class: class}
			data := &tasks.JenkinsTaskData{Options: options, RegexEnricher: api.NewRegexEnricher()}
			e2ehelper.VerifyConnectionIsolation(d, models.JenkinsStage{}, models.JenkinsBuild{}, tasks.StagesClauses(options),
				func() { d.Subtask(tasks.ConvertStagesMeta, data) }, map[schema.Tabler]int64{devops.CICDTask{}: 2})
		})
	}
}
