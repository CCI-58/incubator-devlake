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
	"os"

	"github.com/apache/incubator-devlake/core/dal"
	"github.com/apache/incubator-devlake/core/errors"
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

func (sourceControlRow) TableName() string { return "_devlake_cci_source_control" }

type sourceControlStore struct{ db dal.Dal }

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

var sourceControl *sourcecontrol.Control

func initSourceControl() {
	errors.Must(db.AutoMigrate(&sourceControlRow{}))
	var row sourceControlRow
	err := db.First(&row, dal.Where("id = ?", 1))
	if db.IsErrorNotFound(err) {
		errors.Must(db.Create(&sourceControlRow{ID: 1, Blueprints: "[]"}))
	} else {
		errors.Must(err)
	}
	// The control credential is deliberately not placed in API-editable config.
	sourceControl = sourcecontrol.New(sourceControlStore{db: db}, os.Getenv("CCI_SOURCE_CONTROL_KEY"))
}
func SourceControl() *sourcecontrol.Control { return sourceControl }

func sourcePipeline(id uint64) (func(), errors.Error) {
	if sourceControl == nil {
		return nil, errors.HttpStatus(503).New("source control not initialized")
	}
	release, err := sourceControl.Pipeline(id)
	if err == sourcecontrol.ErrHeld {
		return nil, errors.HttpStatus(409).New("source configuration is being applied")
	}
	if err != nil {
		return nil, errors.HttpStatus(503).New("source control unavailable")
	}
	return release, nil
}
