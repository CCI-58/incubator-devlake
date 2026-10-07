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
	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
	"github.com/apache/incubator-devlake/impls/dalgorm"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"os"
	"strings"
	"testing"
)

func TestResolutionMysqlPersistence(t *testing.T) {
	dsn := os.Getenv("TEST_SOURCE_CONTROL_MYSQL_DSN")
	if dsn == "" {
		t.Skip("isolated MySQL DSN not configured")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, model := range []interface{}{&sourceControlResolution{}, &sourceControlCancellation{}, &sourceControlRow{}} {
		if err = db.Migrator().DropTable(model); err != nil {
			t.Fatal(err)
		}
		if err = db.AutoMigrate(model); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Create(&sourceControlRow{ID: 1, Blueprints: "[]"}).Error; err != nil {
		t.Fatal(err)
	}
	store := sourceControlStore{db: dalgorm.NewDalgorm(db)}
	secret := strings.Repeat("s", 32)
	op := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	proof := "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee"
	next := "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	c := sourcecontrol.New(store, secret)
	if _, err = c.Acquire(secret, op, []uint64{1}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Quiesce(secret, op, proof, []uint64{1}); err != nil {
		t.Fatal(err)
	}
	c = sourcecontrol.New(sourceControlStore{db: dalgorm.NewDalgorm(db)}, secret)
	r, err := c.ResolutionStatus(secret, op, proof)
	if err != nil || r.Phase != sourcecontrol.Quiesced {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = c.Write(sourcecontrol.Token(secret, op)); err != sourcecontrol.ErrHeld {
		t.Fatal(err)
	}
	r.Evidence = next
	if err = store.SaveResolution(r); err != sourcecontrol.ErrHeld {
		t.Fatal(err)
	}
	if _, err = c.ReleaseResolution(secret, op, proof); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Acquire(secret, next, nil); err != nil {
		t.Fatal(err)
	}
	c = sourcecontrol.New(sourceControlStore{db: dalgorm.NewDalgorm(db)}, secret)
	r, err = c.ReleaseResolution(secret, op, proof)
	if err != nil || r.Phase != sourcecontrol.Released {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = c.Check(secret, next); err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.Cancelled(op)
	if err != nil || !cancelled {
		t.Fatalf("cancelled=%v err=%v", cancelled, err)
	}
}
