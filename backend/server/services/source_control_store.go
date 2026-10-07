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
	"encoding/json"
	"github.com/apache/incubator-devlake/core/dal"
	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
)

// Runtime control metadata, bootstrapped after lockDatabase and before API or
// scheduler startup, like LockingHistory. Never cleared by restart/migration.
type sourceControlRow struct {
	ID         uint64 `gorm:"primaryKey;autoIncrement:false;comment:Singleton fence identifier"`
	Operation  string `gorm:"type:varchar(36);not null;comment:CCI immutable operation revision"`
	Blueprints string `gorm:"type:text;not null;comment:Protected blueprint identifiers JSON"`
	Held       bool   `gorm:"not null;comment:Explicit completion required to release"`
}

// SourceControlTable holds the singleton fence row and must survive data resets.
const SourceControlTable = "_devlake_cci_source_control"

func (sourceControlRow) TableName() string { return SourceControlTable }

type sourceControlCancellation struct {
	Operation string `gorm:"primaryKey;type:varchar(36);comment:Permanently cancelled CCI operation revision"`
}

func (sourceControlCancellation) TableName() string {
	return "_devlake_cci_source_control_cancellations"
}

type sourceControlStore struct{ db dal.Dal }

func (s sourceControlStore) Cancelled(operation string) (bool, error) {
	var row sourceControlCancellation
	err := s.db.First(&row, dal.Where("operation = ?", operation))
	if s.db.IsErrorNotFound(err) {
		return false, nil
	}
	return err == nil, err
}
func (s sourceControlStore) Cancel(operation string) error {
	exists, err := s.Cancelled(operation)
	if err != nil || exists {
		return err
	}
	return s.db.Create(&sourceControlCancellation{Operation: operation})
}

func (s sourceControlStore) Load() (sourcecontrol.State, error) {
	var row sourceControlRow
	if err := s.db.First(&row, dal.Where("id = ?", 1)); err != nil {
		return sourcecontrol.State{}, err
	}
	var ids []uint64
	if err := json.Unmarshal([]byte(row.Blueprints), &ids); err != nil {
		return sourcecontrol.State{}, err
	}
	return sourcecontrol.State{Operation: row.Operation, Blueprints: ids, Held: row.Held}, nil
}
func (s sourceControlStore) Save(state sourcecontrol.State) error {
	payload, err := json.Marshal(state.Blueprints)
	if err != nil {
		return err
	}
	return s.db.UpdateColumns(&sourceControlRow{}, []dal.DalSet{
		{ColumnName: "operation", Value: state.Operation},
		{ColumnName: "blueprints", Value: string(payload)},
		{ColumnName: "held", Value: state.Held},
	}, dal.Where("id = ?", 1))
}

// Immutable operation/evidence pairing; receipts survive singleton replacement.
const SourceControlResolutionTable = "_devlake_cci_source_control_resolutions"

type sourceControlResolution struct {
	Operation  string `gorm:"primaryKey;type:varchar(36);comment:CCI operation revision"`
	Evidence   string `gorm:"type:varchar(36);not null;comment:Immutable quiescence evidence UUID"`
	Blueprints string `gorm:"type:text;not null;comment:Protected blueprint identifiers JSON"`
	Phase      string `gorm:"type:varchar(16);not null;comment:QUIESCED RELEASING or RELEASED"`
}

func (sourceControlResolution) TableName() string { return SourceControlResolutionTable }
func (s sourceControlStore) LoadResolution(operation string) (sourcecontrol.Resolution, bool, error) {
	var row sourceControlResolution
	err := s.db.First(&row, dal.Where("operation = ?", operation))
	if s.db.IsErrorNotFound(err) {
		return sourcecontrol.Resolution{}, false, nil
	}
	if err != nil {
		return sourcecontrol.Resolution{}, false, err
	}
	var ids []uint64
	if err := json.Unmarshal([]byte(row.Blueprints), &ids); err != nil {
		return sourcecontrol.Resolution{}, false, err
	}
	return sourcecontrol.Resolution{Operation: row.Operation, Evidence: row.Evidence, Blueprints: ids, Phase: row.Phase}, true, nil
}
func (s sourceControlStore) SaveResolution(next sourcecontrol.Resolution) error {
	previous, found, err := s.LoadResolution(next.Operation)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(next.Blueprints)
	if err != nil {
		return err
	}
	if !found {
		if next.Phase != sourcecontrol.Quiesced {
			return sourcecontrol.ErrInput
		}
		return s.db.Create(&sourceControlResolution{Operation: next.Operation, Evidence: next.Evidence, Blueprints: string(payload), Phase: next.Phase})
	}
	oldPayload, err := json.Marshal(previous.Blueprints)
	if err != nil {
		return err
	}
	if previous.Evidence != next.Evidence || string(oldPayload) != string(payload) ||
		!((previous.Phase == sourcecontrol.Quiesced && next.Phase == sourcecontrol.Releasing) || (previous.Phase == sourcecontrol.Releasing && next.Phase == sourcecontrol.Released)) {
		return sourcecontrol.ErrHeld
	}
	return s.db.UpdateColumns(&sourceControlResolution{}, []dal.DalSet{{ColumnName: "phase", Value: next.Phase}}, dal.Where("operation = ? AND evidence = ? AND phase = ?", next.Operation, next.Evidence, previous.Phase))
}
