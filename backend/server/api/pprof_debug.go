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
	"net/http/pprof"
	"os"
	"strconv"

	"github.com/apache/incubator-devlake/impls/logruslog"
)

// pprofDebugAddr is intentionally loopback-only: it must never become
// reachable from the pod network (other pods), a Kubernetes Service, or an
// Ingress, no matter what routes get added to those later. The only
// supported access paths are `kubectl exec ... -- curl` (runs inside the
// container's own network namespace) and `kubectl port-forward` (tunnels
// through the Kubernetes API server into the pod's namespace), both already
// gated by cluster RBAC. See docs/devlake-startup-hang-runbook.md (GitOps
// repo) and C59-1192 for the rationale.
const pprofDebugAddr = "127.0.0.1:6060"

// runPprofServer starts the net/http/pprof debug endpoints on pprofDebugAddr,
// independent of the main API port/router. It is called as early as possible
// in CreateAndRunApiServer (before Init()/InitExecuteMigration()) so that a
// hang during plugin initialization or the DB migration check can still be
// inspected live via pprof, instead of only via a destructive SIGQUIT dump.
//
// Disabled by default; opt in with ENABLE_PPROF=true (parsed the same way as
// ENABLE_STACKTRACE in core/errors/crdb_impl.go).
func runPprofServer() {
	enable, exists := os.LookupEnv("ENABLE_PPROF")
	if !exists {
		return
	}
	if on, _ := strconv.ParseBool(enable); !on {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	go func() {
		logruslog.Global.Printf("pprof debug server listening on %s (loopback-only, not reachable from outside the pod)", pprofDebugAddr)
		if err := http.ListenAndServe(pprofDebugAddr, mux); err != nil {
			logruslog.Global.Printf("pprof debug server exited: %v", err)
		}
	}()
}
