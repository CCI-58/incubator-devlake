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
	"os"
	"testing"
)

func TestPprofEnabled(t *testing.T) {
	tests := []struct {
		name  string
		unset bool
		value string
		want  bool
	}{
		{name: "unset", unset: true, want: false},
		{name: "empty string", value: "", want: false},
		{name: "false", value: "false", want: false},
		{name: "not a bool", value: "abc", want: false},
		{name: "true", value: "true", want: true},
		{name: "1 (ParseBool true form)", value: "1", want: true},
		{name: "TRUE (ParseBool is case-insensitive)", value: "TRUE", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unset {
				_ = os.Unsetenv("ENABLE_PPROF")
			} else {
				t.Setenv("ENABLE_PPROF", tt.value)
			}
			if got := pprofEnabled(); got != tt.want {
				t.Fatalf("pprofEnabled() = %v, want %v (ENABLE_PPROF=%q unset=%v)", got, tt.want, tt.value, tt.unset)
			}
		})
	}
}

func TestNewPprofMux(t *testing.T) {
	// httptest.NewServer binds an ephemeral port and tears it down via
	// defer srv.Close(), so this never touches the real pprofDebugAddr and
	// is safe under -count=2 or a parallel test run.
	srv := httptest.NewServer(newPprofMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET /debug/pprof/ failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /debug/pprof/, got %d", resp.StatusCode)
	}
}

func TestPprofDebugAddrIsLoopbackOnly(t *testing.T) {
	if pprofDebugAddr != "127.0.0.1:6060" {
		t.Fatalf("pprofDebugAddr changed to %q; it must stay loopback-only (127.0.0.1), never \"0.0.0.0\" or a bare \":PORT\"", pprofDebugAddr)
	}
}
