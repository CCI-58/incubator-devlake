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

	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
	"github.com/gin-gonic/gin"
)

const controlPath = "/cci/source-control"
const controlKeyHeader = "X-CCI-Control-Key"
const operationHeader = "X-CCI-Source-Token"
const resolutionHeader = "X-CCI-Resolution-Token"

func sourceControlError(ctx *gin.Context, err error) {
	status := http.StatusConflict
	if err == sourcecontrol.ErrUnavailable {
		status = http.StatusServiceUnavailable
	}
	if err == sourcecontrol.ErrInput {
		status = http.StatusBadRequest
	}
	ctx.AbortWithStatusJSON(status, gin.H{"message": "source control unavailable or conflicting"})
}

func registerSourceControl(router *gin.Engine, control *sourcecontrol.Control, ready func() bool) {
	// All control routes require the deployment credential. API authentication
	// additionally applies when reached via the authenticated /rest group.
	router.GET(controlPath+"/capabilities", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		quiescence := 0
		if control.SupportsQuiescence() {
			quiescence = 1
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "cancellation": 1, "quiescence": quiescence})
	})
	router.POST(controlPath+"/:operation/cancel", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		if err := control.Cancel(ctx.GetHeader(controlKeyHeader), ctx.Param("operation")); err != nil {
			sourceControlError(ctx, err)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "operation": ctx.Param("operation"), "cancelled": true})
	})
	registerSourceResolution(router, control, ready)
	router.POST(controlPath, func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		var request struct {
			Operation  string   `json:"operation"`
			Blueprints []uint64 `json:"blueprints"`
		}
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 32768)
		if ctx.ShouldBindJSON(&request) != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		state, err := control.Acquire(ctx.GetHeader(controlKeyHeader), request.Operation, request.Blueprints)
		if err != nil {
			sourceControlError(ctx, err)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "operation": state.Operation, "blueprints": state.Blueprints, "held": state.Held})
	})
	router.GET(controlPath+"/:operation", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		state, err := control.Check(ctx.GetHeader(controlKeyHeader), ctx.Param("operation"))
		if err != nil {
			sourceControlError(ctx, err)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "operation": state.Operation, "blueprints": state.Blueprints, "held": state.Held})
	})
	router.DELETE(controlPath+"/:operation", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err := control.Release(ctx.GetHeader(controlKeyHeader), ctx.Param("operation")); err != nil {
			sourceControlError(ctx, err)
			return
		}
		ctx.Status(http.StatusNoContent)
	})
}

func sourceControlWrites(control *sourcecontrol.Control) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// This middleware is installed AFTER the control endpoints; normal APIs
		// cannot skip it with path aliases or a spoofed control-path prefix.
		if ctx.Request.Method == http.MethodGet || ctx.Request.Method == http.MethodHead || ctx.Request.Method == http.MethodOptions {
			if ctx.FullPath() != "/proceed-db-migration" {
				ctx.Next()
				return
			}
		}
		if control == nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		var release func()
		var err error
		if ctx.GetHeader(resolutionHeader) != "" {
			if ctx.GetHeader(operationHeader) != "" {
				ctx.AbortWithStatus(http.StatusBadRequest)
				return
			}
			release, err = control.ResolutionWrite(ctx.GetHeader(resolutionHeader))
		} else {
			release, err = control.Write(ctx.GetHeader(operationHeader))
		}
		if err != nil {
			sourceControlError(ctx, err)
			return
		}
		defer release()
		ctx.Next()
	}
}
