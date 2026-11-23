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
	"github.com/apache/incubator-devlake/server/services"
	"github.com/gin-gonic/gin"
	"net/http"
)

func registerCollectionReceipts(router *gin.Engine, control *sourcecontrol.Control, ready func() bool) {
	router.GET("/cci/collection-requests/capabilities", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"protocol": 1, "receipts": 1})
	})
	router.POST("/cci/collection-requests/:request/:action", func(ctx *gin.Context) {
		if control == nil || !control.Authorized(ctx.GetHeader(controlKeyHeader)) {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !ready() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		action := ctx.Param("action")
		if action != "start" && action != "resolve" && action != "cancel" {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		var body struct {
			Blueprint uint64 `json:"blueprintId"`
		}
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 1024)
		if ctx.ShouldBindJSON(&body) != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		receipt, err := services.ResolveOrStartCollection(ctx.Param("request"), body.Blueprint, action != "start")
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"message": "collection request unconfirmed"})
			return
		}
		if action == "cancel" && receipt.Pipeline > 0 && !receipt.Ended {
			if services.CancelReceiptPipeline(receipt.Pipeline) != nil {
				ctx.AbortWithStatus(http.StatusServiceUnavailable)
				return
			}
			// The receipt still says ended=false. Cancellation acknowledgement is never terminal proof.
		}
		ctx.JSON(http.StatusOK, receipt)
	})
}
