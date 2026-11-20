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

package shared

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/apache/incubator-devlake/core/errors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Extract the production leaf literal so fork changes cannot silently retain an obsolete fixture.
func TestPendingRejectionContract(t *testing.T) {
	tree, err := parser.ParseFile(token.NewFileSet(), "../../services/pipeline_helper.go", nil, 0)
	require.NoError(t, err)
	var leaf string
	ast.Inspect(tree, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "createDbPipelineWithoutFence" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "New" {
				return true
			}
			kind, ok := selector.X.(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "BadInput" {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			require.NoError(t, err)
			require.Empty(t, leaf, "Review multiple BadInput.New leaves before changing the CCI contract")
			leaf = value
			return true
		})
		return false
	})
	require.NotEmpty(t, leaf)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ApiOutputError(ctx, errors.Default.Wrap(errors.BadInput.New(leaf), "error triggering blueprint"))
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var actual map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &actual))
	fixture, err := os.ReadFile("testdata/devlake-pending-rejection.json")
	require.NoError(t, err)
	var expected map[string]interface{}
	require.NoError(t, json.Unmarshal(fixture, &expected))
	// message contains optional stacks; consumers require its type, not its unstable text.
	require.IsType(t, "", actual["message"])
	actual["message"] = expected["message"]
	require.Equal(t, expected, actual)
}
