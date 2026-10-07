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
	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
	"os"
)

var sourceControl *sourcecontrol.Control

func initSourceControl() {
	errors.Must(db.AutoMigrate(&sourceControlRow{}))
	errors.Must(db.AutoMigrate(&sourceControlCancellation{}))
	errors.Must(db.AutoMigrate(&sourceControlResolution{}))
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
