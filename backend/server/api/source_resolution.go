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
	"github.com/apache/incubator-devlake/helpers/sourcecontrol"
	"github.com/gin-gonic/gin"
	"net/http"
)

func registerSourceResolution(router *gin.Engine, control *sourcecontrol.Control, ready func() bool) {
	authorize := func(ctx *gin.Context) bool {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return false
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return false
		}
		return true
	}
	respond := func(ctx *gin.Context, r sourcecontrol.Resolution, err error) {
		if err != nil {
			sourceControlError(ctx, err)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "quiescence": 1, "operation": r.Operation, "evidence": r.Evidence, "blueprints": r.Blueprints, "phase": r.Phase})
	}
	router.POST(controlPath+"/:operation/quiesce", func(ctx *gin.Context) {
		if !authorize(ctx) {
			return
		}
		var request struct {
			Evidence   string   `json:"evidence"`
			Blueprints []uint64 `json:"blueprints"`
		}
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 32768)
		if ctx.ShouldBindJSON(&request) != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		r, err := control.Quiesce(ctx.GetHeader(controlKeyHeader), ctx.Param("operation"), request.Evidence, request.Blueprints)
		respond(ctx, r, err)
	})
	router.GET(controlPath+"/:operation/resolutions/:evidence", func(ctx *gin.Context) {
		if !authorize(ctx) {
			return
		}
		r, err := control.ResolutionStatus(ctx.GetHeader(controlKeyHeader), ctx.Param("operation"), ctx.Param("evidence"))
		respond(ctx, r, err)
	})
	router.POST(controlPath+"/:operation/resolutions/:evidence/release", func(ctx *gin.Context) {
		if !authorize(ctx) {
			return
		}
		r, err := control.ReleaseResolution(ctx.GetHeader(controlKeyHeader), ctx.Param("operation"), ctx.Param("evidence"))
		respond(ctx, r, err)
	})
}
