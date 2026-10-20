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
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRunPprofServer(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		_ = os.Unsetenv("ENABLE_PPROF")
		runPprofServer()
		// give any (incorrectly) started goroutine a moment to bind
		time.Sleep(50 * time.Millisecond)
		if conn, err := net.Dial("tcp", pprofDebugAddr); err == nil {
			_ = conn.Close()
			t.Fatalf("pprof server should not be listening when ENABLE_PPROF is unset")
		}
	})

	t.Run("enabled listens on loopback only", func(t *testing.T) {
		t.Setenv("ENABLE_PPROF", "true")
		runPprofServer()

		var resp *http.Response
		var err error
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			resp, err = http.Get("http://" + pprofDebugAddr + "/debug/pprof/")
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("expected pprof server to be reachable on %s, got: %v", pprofDebugAddr, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from /debug/pprof/, got %d", resp.StatusCode)
		}
	})
}
