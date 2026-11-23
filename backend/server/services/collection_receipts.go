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

package services

import (
	"github.com/apache/incubator-devlake/core/dal"
	"github.com/apache/incubator-devlake/core/errors"
	"github.com/apache/incubator-devlake/core/models"
	"regexp"
	"sync"
)

// Like source-control this relies on DevLake's one backend process per database.
// Resolve drains any in-flight admission before creating a permanent tombstone.
var collectionReceiptLock sync.Mutex
var receiptIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type collectionReceiptRow struct {
	Request   string `gorm:"type:varchar(36);primaryKey;comment:Immutable CCI request identity"`
	Blueprint uint64 `gorm:"not null;comment:Exact protected blueprint"`
	Pipeline  uint64 `gorm:"not null;comment:Atomically created pipeline or zero for retired request"`
}

func (collectionReceiptRow) TableName() string { return "_devlake_cci_collection_receipts" }

type CollectionReceipt struct {
	Protocol  int    `json:"protocol"`
	Request   string `json:"request"`
	Blueprint uint64 `json:"blueprintId"`
	Pipeline  uint64 `json:"pipelineId"`
	State     string `json:"state"`
	Ended     bool   `json:"ended"`
	Succeeded bool   `json:"succeeded"`
}

// resolve=true never starts work: a missing request becomes permanently RETIRED.
// Late or duplicate POSTs can never create a second pipeline for this identity.
func ResolveOrStartCollection(request string, blueprint uint64, resolve bool) (CollectionReceipt, errors.Error) {
	var empty CollectionReceipt
	if !receiptIDPattern.MatchString(request) || blueprint == 0 {
		return empty, errors.BadInput.New("invalid collection identity")
	}
	collectionReceiptLock.Lock()
	defer collectionReceiptLock.Unlock()
	var row collectionReceiptRow
	err := db.First(&row, dal.Where("request = ?", request))
	if err == nil {
		if row.Blueprint != blueprint {
			return empty, errors.HttpStatus(409).New("collection identity conflict")
		}
		return observeCollectionReceipt(row)
	}
	if !db.IsErrorNotFound(err) {
		return empty, errors.HttpStatus(503).New("collection receipt unavailable")
	}
	row = collectionReceiptRow{Request: request, Blueprint: blueprint}
	if resolve {
		if err = db.Create(&row); err != nil {
			return empty, errors.HttpStatus(503).New("collection retirement unavailable")
		}
		return observeCollectionReceipt(row)
	}
	bp, err := GetBlueprint(blueprint, false)
	if err != nil {
		return empty, err
	}
	_, err = createPipelineByBlueprintWithReceipt(bp, &models.SyncPolicy{TriggerSyncPolicy: models.TriggerSyncPolicy{FullSync: true, SkipCollectors: false}},
		func(tx dal.Dal, pipeline uint64) errors.Error {
			row.Pipeline = pipeline
			return tx.Create(&row)
		})
	if err != nil {
		return empty, err
	}
	return observeCollectionReceipt(row)
}
func receiptView(row collectionReceiptRow) CollectionReceipt {
	state := "BOUND"
	if row.Pipeline == 0 {
		state = "RETIRED"
	}
	return CollectionReceipt{Protocol: 1, Request: row.Request, Blueprint: row.Blueprint, Pipeline: row.Pipeline, State: state}
}

// A cancel acknowledgement or a pipeline status alone is not an end certificate.
func observeCollectionReceipt(row collectionReceiptRow) (CollectionReceipt, errors.Error) {
	result := receiptView(row)
	if row.Pipeline == 0 {
		return result, nil
	}
	pipeline, err := GetDbPipeline(row.Pipeline)
	if err != nil || pipeline.BlueprintId != row.Blueprint || !pipeline.FullSync {
		return CollectionReceipt{}, errors.HttpStatus(503).New("collection receipt mismatch")
	}
	if pipeline.FinishedAt == nil {
		return result, nil
	}
	terminal := []string{models.TASK_COMPLETED, models.TASK_FAILED, models.TASK_CANCELLED, models.TASK_PARTIAL}
	terminalState := false
	for _, state := range terminal {
		if pipeline.Status == state {
			terminalState = true
		}
	}
	if !terminalState {
		return result, nil
	}
	total, err := db.Count(dal.From(&models.Task{}), dal.Where("pipeline_id = ?", row.Pipeline))
	if err != nil {
		return result, err
	}
	unfinished, err := db.Count(dal.From(&models.Task{}), dal.Where("pipeline_id = ? AND (status IS NULL OR status NOT IN ? OR finished_at IS NULL)", row.Pipeline, terminal))
	if err != nil {
		return result, err
	}
	unfinishedSubs, err := db.Count(dal.From(&models.Subtask{}), dal.Join("JOIN _devlake_tasks t ON t.id=_devlake_subtasks.task_id"), dal.Where("t.pipeline_id=? AND _devlake_subtasks.finished_at IS NULL", row.Pipeline))
	if err != nil {
		return result, err
	}
	if total <= 0 || total != int64(pipeline.TotalTasks) || unfinished != 0 || unfinishedSubs != 0 {
		return result, nil
	}
	result.Ended = true
	result.Succeeded = pipeline.Status == models.TASK_COMPLETED
	if result.Succeeded {
		badTasks, err := db.Count(dal.From(&models.Task{}), dal.Where("pipeline_id=? AND (status<>? OR NOT EXISTS (SELECT 1 FROM _devlake_subtasks s WHERE s.task_id=_devlake_tasks.id))", row.Pipeline, models.TASK_COMPLETED))
		if err != nil {
			return CollectionReceipt{}, err
		}
		badSubs, err := db.Count(dal.From(&models.Subtask{}), dal.Join("JOIN _devlake_tasks t ON t.id=_devlake_subtasks.task_id"), dal.Where("t.pipeline_id=? AND (_devlake_subtasks.is_failed IS NULL OR _devlake_subtasks.is_failed<>0)", row.Pipeline))
		if err != nil {
			return CollectionReceipt{}, err
		}
		if badTasks != 0 || badSubs != 0 {
			result.Ended = false
			result.Succeeded = false
		}
	}
	return result, nil
}
