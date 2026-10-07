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

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
	"github.com/gin-gonic/gin"
)

type apiControlStore struct {
	journal   map[string]sourcecontrol.Resolution
	state     sourcecontrol.State
	cancelled map[string]bool
}

func (s *apiControlStore) Cancelled(op string) (bool, error) { return s.cancelled[op], nil }
func (s *apiControlStore) Cancel(op string) error {
	if s.cancelled == nil {
		s.cancelled = map[string]bool{}
	}
	s.cancelled[op] = true
	return nil
}

func (s *apiControlStore) Load() (sourcecontrol.State, error)   { return s.state, nil }
func (s *apiControlStore) Save(state sourcecontrol.State) error { s.state = state; return nil }

func TestSourceControlRoutesAndMutationGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := strings.Repeat("s", 32)
	operation := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	router := gin.New()
	// Existing API authentication must precede control registration too.
	router.Use(func(ctx *gin.Context) {
		if ctx.GetHeader("Authorization") != "Bearer api-key" {
			ctx.AbortWithStatus(401)
			return
		}
		ctx.Next()
	})
	control := sourcecontrol.New(&apiControlStore{}, key)
	registerSourceControl(router, control, func() bool { return true })
	router.Use(sourceControlWrites(control))
	handler := func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) }
	router.PATCH("/blueprints/1", handler)
	router.POST("/cci/source-control-spoof", handler)
	router.GET("/proceed-db-migration", handler)
	router.GET("/blueprints/1", handler)
	request := func(method, path, body, apiKey, controlKey, token string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", apiKey)
		req.Header.Set(controlKeyHeader, controlKey)
		req.Header.Set(operationHeader, token)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("%s %s: status %d, want %d", method, path, recorder.Code, want)
		}
	}
	payload := `{"operation":"` + operation + `","blueprints":[1]}`
	request("POST", controlPath, payload, "", key, "", 401)
	request("POST", controlPath, payload, "Bearer api-key", "", "", 403)
	request("POST", controlPath, payload, "Bearer api-key", key, "", 200)
	request("PATCH", "/blueprints/1", "{}", "Bearer api-key", "", "", 409)
	request("POST", "/cci/source-control-spoof", "{}", "Bearer api-key", "", "", 409)
	request("GET", "/proceed-db-migration", "", "Bearer api-key", "", "", 409)
	request("GET", "/blueprints/1", "", "Bearer api-key", "", "", 204)
	token := sourcecontrol.Token(key, operation)
	request("PATCH", "/blueprints/1", "{}", "Bearer api-key", "", token, 204)
	request("GET", controlPath+"/"+operation, "", "Bearer api-key", key, "", 200)
	request("DELETE", controlPath+"/"+operation, "", "Bearer api-key", "", "", 403)
	request("DELETE", controlPath+"/"+operation, "", "Bearer api-key", key, "", 204)
	request("PATCH", "/blueprints/1", "{}", "Bearer api-key", "", token, 409)
	request("PATCH", "/blueprints/1", "{}", "Bearer api-key", "", "", 204)
	request("GET", controlPath+"/capabilities", "", "Bearer api-key", key, "", 200)
	request("POST", controlPath+"/"+operation+"/cancel", "{}", "Bearer api-key", "", "", 403)
	request("POST", controlPath+"/"+operation+"/cancel", "{}", "Bearer api-key", key, "", 200)
	request("POST", controlPath+"/"+operation+"/cancel", "{}", "Bearer api-key", key, "", 200)
	request("POST", controlPath, payload, "Bearer api-key", key, "", 409)
}

func (s *apiControlStore) LoadResolution(op string) (sourcecontrol.Resolution, bool, error) {
	r, ok := s.journal[op]
	return r, ok, nil
}
func (s *apiControlStore) SaveResolution(r sourcecontrol.Resolution) error {
	if s.journal == nil {
		s.journal = map[string]sourcecontrol.Resolution{}
	}
	s.journal[r.Operation] = r
	return nil
}
func TestResolutionRoutesAndSeparateWriteToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := strings.Repeat("s", 32)
	op := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	proof := "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee"
	control := sourcecontrol.New(&apiControlStore{}, key)
	router := gin.New()
	registerSourceControl(router, control, func() bool { return true })
	router.Use(sourceControlWrites(control))
	writes := 0
	router.POST("/plugins/github/connections", func(ctx *gin.Context) { writes++; ctx.Status(201) })
	request := func(method, path, body, controlKey, oldToken, recoveryToken string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set(controlKeyHeader, controlKey)
		req.Header.Set(operationHeader, oldToken)
		req.Header.Set(resolutionHeader, recoveryToken)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s status %d want %d", method, path, w.Code, want)
		}
	}
	request("POST", controlPath+"/"+op+"/quiesce", `{"evidence":"`+proof+`","blueprints":[1]}`, "", "", "", 403)
	request("POST", controlPath+"/"+op+"/quiesce", `{"evidence":"`+proof+`","blueprints":[1]}`, key, "", "", 200)
	old := sourcecontrol.Token(key, op)
	recovery := sourcecontrol.ResolutionToken(key, op, proof)
	request("POST", "/plugins/github/connections", "{}", "", old, "", 409)
	request("POST", "/plugins/github/connections", "{}", "", "", "", 409)
	request("POST", "/plugins/github/connections", "{}", "", old, recovery, 400)
	request("POST", "/plugins/github/connections", "{}", "", "", recovery, 201)
	path := controlPath + "/" + op + "/resolutions/" + proof
	request("GET", path, "", key, "", "", 200)
	request("DELETE", controlPath+"/"+op, "", key, "", "", 409)
	request("POST", controlPath+"/"+op+"/cancel", "{}", key, "", "", 409)
	request("POST", path+"/release", "{}", key, "", "", 200)
	request("POST", path+"/release", "{}", key, "", "", 200)
	request("POST", "/plugins/github/connections", "{}", "", "", recovery, 409)
	if writes != 1 {
		t.Fatalf("unexpected writes: %d", writes)
	}
}
