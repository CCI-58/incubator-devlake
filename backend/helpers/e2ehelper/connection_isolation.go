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

package e2ehelper

import (
	"encoding/json"
	"sort"

	"github.com/apache/incubator-devlake/core/dal"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"
)

// VerifyConnectionIsolation compares the actual converter with and without
// colliding connection-2 fixtures. Count shares the production FROM/JOIN/WHERE
// clauses, so an upsert cannot hide duplicated input. The fixture owns both
// input tables and uses connection 1 for the selected scope.
func VerifyConnectionIsolation(t *DataFlowTester, child, parent schema.Tabler, clauses []dal.Clause, run func(), products map[schema.Tabler]int64) {
	type savedRows struct {
		table schema.Tabler
		rows  []map[string]interface{}
	}
	var foreign []savedRows
	for _, table := range []schema.Tabler{child, parent} {
		var rows []map[string]interface{}
		require.NoError(t.T, t.Db.Table(table.TableName()).Where("connection_id = ?", 2).Find(&rows).Error)
		require.NotEmpty(t.T, rows)
		foreign = append(foreign, savedRows{table, rows})
		require.NoError(t.T, t.Db.Table(table.TableName()).Where("connection_id = ?", 2).Delete(map[string]interface{}{}).Error)
	}
	count := func(expected int64) {
		n, err := t.Dal.Count(clauses...)
		require.NoError(t.T, err)
		require.Equal(t.T, expected, n, "converter input cardinality")
	}
	snapshot := func(table schema.Tabler, expected int64) []string {
		var rows []map[string]interface{}
		require.NoError(t.T, t.Db.Table(table.TableName()).Find(&rows).Error)
		require.Equal(t.T, expected, int64(len(rows)), table.TableName())
		result := make([]string, 0, len(rows))
		for _, row := range rows {
			// These are persistence timestamps, not source/business dates.
			delete(row, "created_at")
			delete(row, "updated_at")
			encoded, err := json.Marshal(row)
			require.NoError(t.T, err)
			result = append(result, string(encoded))
		}
		sort.Strings(result)
		return result
	}
	for table := range products {
		t.FlushTabler(table)
	}
	count(2)
	run()
	baseline := make(map[schema.Tabler][]string)
	for table, n := range products {
		baseline[table] = snapshot(table, n)
	}
	for _, saved := range foreign {
		for _, row := range saved.rows {
			require.NoError(t.T, t.Db.Table(saved.table.TableName()).Create(row).Error)
		}
	}
	count(2)
	// Rebuild from empty products with colliding parents/children present.
	for table := range products {
		t.FlushTabler(table)
	}
	for pass := 0; pass < 2; pass++ {
		run()
		for table, n := range products {
			require.Equal(t.T, baseline[table], snapshot(table, n), table.TableName())
		}
	}
	// Only foreign children remain. They must not be relabelled as connection 1.
	require.NoError(t.T, t.Db.Table(child.TableName()).Where("connection_id = ?", 1).Delete(map[string]interface{}{}).Error)
	count(0)
	for table := range products {
		t.FlushTabler(table)
	}
	run()
	for table := range products {
		snapshot(table, 0)
	}
}
