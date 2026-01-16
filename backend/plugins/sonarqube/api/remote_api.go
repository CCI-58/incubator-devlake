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
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/apache/incubator-devlake/core/errors"
	"github.com/apache/incubator-devlake/core/plugin"
	"github.com/apache/incubator-devlake/helpers/pluginhelper/api"
	dsmodels "github.com/apache/incubator-devlake/helpers/pluginhelper/api/models"
	"github.com/apache/incubator-devlake/plugins/sonarqube/models"
)

type SonarqubeRemotePagination struct {
	Page     int `json:"p"`
	PageSize int `json:"ps"`
}

// categorizeSonarqubeError はSonarQube API呼び出し時のエラーを分類し、適切なエラーメッセージを返す
// エラーの種類に応じてERROR（インフラ/コード起因）またはWARN（ユーザー設定で解消可能）レベルのエラーを返す
func categorizeSonarqubeError(err error, res *http.Response, endpoint string) errors.Error {
	if err != nil {
		errMsg := err.Error()

		// DNS解決失敗
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return errors.Default.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーのホスト名を解決できません: %s - ホスト名またはDNS設定を確認してください", endpoint))
		}

		// 接続拒否 (Connection Refused)
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			if opErr.Op == "dial" {
				return errors.Default.Wrap(err, fmt.Sprintf(
					"SonarQubeサーバーへの接続が拒否されました: %s - サーバーが起動しているか、ポート設定を確認してください", endpoint))
			}
		}

		// 接続タイムアウト
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return errors.Timeout.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーへの接続がタイムアウトしました: %s - ネットワーク接続またはファイアウォール設定を確認してください", endpoint))
		}

		// TLS/SSL証明書エラー
		var certErr *x509.CertificateInvalidError
		if errors.As(err, &certErr) {
			return errors.Default.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーの証明書が無効です: %v - 証明書の有効期限または設定を確認してください", certErr))
		}
		var unknownAuthErr x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthErr) {
			return errors.Default.Wrap(err,
				"SonarQubeサーバーの証明書が無効です: 不明な認証局 - 証明書の設定を確認してください")
		}

		// 接続拒否の文字列パターンマッチ（フォールバック）
		if strings.Contains(errMsg, "connection refused") {
			return errors.Default.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーへの接続が拒否されました: %s - サーバーが起動しているか、ポート設定を確認してください", endpoint))
		}

		// タイムアウトの文字列パターンマッチ（フォールバック）
		if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "deadline exceeded") {
			return errors.Timeout.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーへの接続がタイムアウトしました: %s - ネットワーク接続またはファイアウォール設定を確認してください", endpoint))
		}

		// DNS解決失敗の文字列パターンマッチ（フォールバック）
		if strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "lookup") {
			return errors.Default.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーのホスト名を解決できません: %s - ホスト名またはDNS設定を確認してください", endpoint))
		}

		// TLS/SSL証明書エラーの文字列パターンマッチ（フォールバック）
		if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "x509") || strings.Contains(errMsg, "tls") {
			return errors.Default.Wrap(err, fmt.Sprintf(
				"SonarQubeサーバーの証明書が無効です: %s - 証明書の有効期限または設定を確認してください", errMsg))
		}

		// その他の接続エラー
		return errors.Default.Wrap(err, fmt.Sprintf(
			"SonarQubeサーバーへの接続に失敗しました: %s - %s", endpoint, errMsg))
	}

	// HTTPレスポンスのステータスコードによる分類
	if res != nil {
		statusCode := res.StatusCode

		// レスポンスボディを読み取る
		var responseBody string
		if res.Body != nil {
			bodyBytes, readErr := io.ReadAll(res.Body)
			if readErr == nil {
				responseBody = string(bodyBytes)
			}
		}

		switch statusCode {
		case http.StatusUnauthorized:
			// 認証エラー (401) - WARN: ユーザーがトークンを変更することで解消可能
			return errors.Unauthorized.New(
				"SonarQube認証に失敗しました - トークンが無効または期限切れです")
		case http.StatusForbidden:
			// 権限エラー (403) - WARN: ユーザーがトークン権限を変更することで解消可能
			return errors.Forbidden.New(
				"SonarQube APIへのアクセス権限がありません - トークンの権限を確認してください")
		case http.StatusNotFound:
			// Not Found (404) - ERROR: ユーザー設定では解消不可
			return errors.NotFound.New(fmt.Sprintf(
				"SonarQube APIエラー: 404 - エンドポイントが見つかりません: %s", endpoint))
		case http.StatusBadRequest:
			// Bad Request (400) - ERROR: ユーザー設定では解消不可
			return errors.BadInput.New(fmt.Sprintf(
				"SonarQube APIエラー: 400 - リクエストが不正です: %s", responseBody))
		default:
			if statusCode >= 400 && statusCode < 500 {
				// その他の4xxエラー - ERROR
				return errors.HttpStatus(statusCode).New(fmt.Sprintf(
					"SonarQube APIエラー: %d - %s", statusCode, responseBody))
			}
			if statusCode >= 500 {
				// 5xxエラー - ERROR: サーバー側の問題
				return errors.HttpStatus(statusCode).New(fmt.Sprintf(
					"SonarQube APIエラー: %d - サーバーエラーが発生しました: %s", statusCode, responseBody))
			}
		}
	}

	return nil
}

func querySonarqubeProjects(
	apiClient plugin.ApiClient,
	keyword string,
	page SonarqubeRemotePagination,
) (
	children []dsmodels.DsRemoteApiScopeListEntry[models.SonarqubeProject],
	nextPage *SonarqubeRemotePagination,
	err errors.Error,
) {
	if page.PageSize == 0 {
		page.PageSize = 100
	}
	if page.Page == 0 {
		page.Page = 1
	}

	// SonarQube projects/search APIを呼び出し
	res, err := apiClient.Get("projects/search", url.Values{
		"p":  {fmt.Sprintf("%v", page.Page)},
		"ps": {fmt.Sprintf("%v", page.PageSize)},
		"q":  {keyword},
	}, nil)

	// API呼び出しエラーの分類と詳細なエラーメッセージの生成
	if err != nil {
		categorizedErr := categorizeSonarqubeError(err.Unwrap(), nil, "projects/search")
		if categorizedErr != nil {
			err = categorizedErr
		}
		return
	}

	// HTTPステータスコードのチェック
	if res.StatusCode != http.StatusOK {
		categorizedErr := categorizeSonarqubeError(nil, res, "projects/search")
		if categorizedErr != nil {
			err = categorizedErr
			return
		}
	}

	resBody := struct {
		Paging struct {
			PageIndex int `json:"pageIndex"`
			PageSize  int `json:"pageSize"`
			Total     int `json:"total"`
		} `json:"paging"`
		Components []*models.SonarqubeApiProject
	}{}

	// レスポンスのパース
	err = api.UnmarshalResponse(res, &resBody)
	if err != nil {
		// パースエラー - ERROR: コード/データ形式の問題
		err = errors.Default.Wrap(err, "SonarQubeレスポンスの解析に失敗しました")
		return
	}

	for _, project := range resBody.Components {
		children = append(children, dsmodels.DsRemoteApiScopeListEntry[models.SonarqubeProject]{
			Type:     api.RAS_ENTRY_TYPE_SCOPE,
			Id:       fmt.Sprintf("%v", project.ProjectKey),
			ParentId: nil,
			Name:     project.Name,
			FullName: project.Name,
			Data:     project.ConvertApiScope(),
		})
	}

	if resBody.Paging.Total > resBody.Paging.PageIndex*resBody.Paging.PageSize {
		nextPage = &SonarqubeRemotePagination{
			Page:     resBody.Paging.PageIndex + 1,
			PageSize: resBody.Paging.PageSize,
		}
	}

	return
}

func listSonarqubeRemoteScopes(
	connection *models.SonarqubeConnection,
	apiClient plugin.ApiClient,
	groupId string,
	page SonarqubeRemotePagination,
) (
	children []dsmodels.DsRemoteApiScopeListEntry[models.SonarqubeProject],
	nextPage *SonarqubeRemotePagination,
	err errors.Error,
) {
	return querySonarqubeProjects(apiClient, "", page)
}

// RemoteScopes list all available scopes on the remote server
// @Summary list all available scopes on the remote server
// @Description list all available scopes on the remote server
// @Accept application/json
// @Param connectionId path int false "connection ID"
// @Param groupId query string false "group ID"
// @Param pageToken query string false "page Token"
// @Failure 400  {object} shared.ApiBody "Bad Request"
// @Failure 500  {object} shared.ApiBody "Internal Error"
// @Success 200  {object} dsmodels.DsRemoteApiScopeList[models.SonarqubeProject]
// @Tags plugins/sonarqube
// @Router /plugins/sonarqube/connections/{connectionId}/remote-scopes [GET]
func RemoteScopes(input *plugin.ApiResourceInput) (*plugin.ApiResourceOutput, errors.Error) {
	return raScopeList.Get(input)
}

func searchSonarqubeRemoteProjects(
	apiClient plugin.ApiClient,
	params *dsmodels.DsRemoteApiScopeSearchParams,
) (
	children []dsmodels.DsRemoteApiScopeListEntry[models.SonarqubeProject],
	err errors.Error,
) {
	if params.Page == 0 {
		params.Page = 1
	}
	page := SonarqubeRemotePagination{
		Page:     params.Page,
		PageSize: params.PageSize,
	}
	children, _, err = querySonarqubeProjects(apiClient, params.Search, page)
	return
}

// SearchRemoteScopes searches scopes on the remote server
// @Summary searches scopes on the remote server
// @Description searches scopes on the remote server
// @Accept application/json
// @Param connectionId path int false "connection ID"
// @Param search query string false "search"
// @Param page query int false "page number"
// @Param pageSize query int false "page size per page"
// @Failure 400  {object} shared.ApiBody "Bad Request"
// @Failure 500  {object} shared.ApiBody "Internal Error"
// @Success 200  {object} dsmodels.DsRemoteApiScopeList[models.SonarqubeProject] "the parentIds are always null"
// @Tags plugins/sonarqube
// @Router /plugins/sonarqube/connections/{connectionId}/search-remote-scopes [GET]
func SearchRemoteScopes(input *plugin.ApiResourceInput) (*plugin.ApiResourceOutput, errors.Error) {
	return raScopeSearch.Get(input)
}

// @Summary Remote server API proxy
// @Description Forward API requests to the specified remote server
// @Param connectionId path int true "connection ID"
// @Param path path string true "path to a API endpoint"
// @Tags plugins/sonarqube
// @Router /plugins/sonarqube/connections/{connectionId}/proxy/{path} [GET]
func Proxy(input *plugin.ApiResourceInput) (*plugin.ApiResourceOutput, errors.Error) {
	return raProxy.Proxy(input)
}
