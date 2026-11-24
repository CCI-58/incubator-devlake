<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# 収集時間の短縮とツール接続境界の修正計画

## レビュー対象

stagingの収集が長時間待機する原因を調査した結果、直列実行に加え、SonarQubeのSQL結合条件不足による処理行増幅を確認した。追加調査でGitHubとJenkinsにも同種の欠落を確認したため、3プラグインの接続境界の不具合（計11箇所）を1つの独立した実装PRで修正する。承認前に製品コード、DB、稼働設定は変更しない。

本計画は「すべての遅延要因を一括変更する」ものではない。並列数変更は[GitOps #298](https://github.com/CCI-58/GitOps/pull/298)、収集ライフサイクル・receiptは[DevLake #9](https://github.com/CCI-58/incubator-devlake/pull/9)の別スコープとする。これらへの依存を増やさず、性能修正を個別にレビュー・配備できる形にする。

## 調査事実

2026-11-24、staging (`iod-cci-staging`) の配備済みDevLake `530768fb034fd51d728cb7af56ffc5e50bf8567f` に対し、GET、ログ、read-only SQLで確認した。

| 対象 | 観測 |
| --- | --- |
| GitHub pipeline 7820 | 87分45秒。ジョブ142,581件の抽出1,397秒、変換1,191秒（計43分08秒） |
| GitHub pipeline 7821 | 48分32秒。PR commit変換75,758件/580秒、Workflow抽出38,613件/377秒・変換38,612件/338秒 |
| 同blueprintの前日7797 | 61分48秒。今回だけの一過性遅延ではない |
| SonarQube 7822/7824/7828 | 全体23〜25分、コード位置情報変換だけ1,002〜1,051秒、処理行は約11.7万 |
| 同じ取得対象 | GitHub `CCI-58/cci` はconnection 2/10/14、SonarQube `connected_ci` は4/6/9/5で別々に実行 |
| GitHub 7831の現在ログ | EOF 4回、502 3回、各120秒後の再試行。待機指示は計14分相当 |

13:51以降の観測時、SonarQube connection 4 / project `connected_ci` に対するCOUNTは現行結合117,054行、接続IDを結合条件へ加えると21,324行だった（約5.49倍）。履歴の処理件数との小差は観測時点が異なるため。同じ課題キーが複数接続に保存されていることで中間行が増えている。

APIサブタスクの `finishedRecords` はページ/応答数の場合があり、業務データ件数と直接比較しない。参照できた現在Podログは13:01以降のみで、10時台のAPI遅延原因や当時のレート制限は断定できない。瞬間値はDevLake 29m/839Mi、MySQL 499m/1,732Miだったが、過去ピークやCPU/IO飽和を示すものではない。

## コード上の原因と影響

[issue_code_blocks_convertor.go](../../backend/plugins/sonarqube/tasks/issue_code_blocks_convertor.go) の `ConvertIssueCodeBlocks` は次の構造で読む。

```sql
FROM _tool_sonarqube_issue_code_blocks icb
LEFT JOIN _tool_sonarqube_issues i ON i.issue_key = icb.issue_key
WHERE icb.connection_id = ? AND project_key = ?
```

`i.connection_id = icb.connection_id` がないため、他接続の同一課題にも結合する。不要な変換・書き込みが増える。また、自接続に対応課題がなく他接続だけに存在する場合の誤った取り込みも回帰テストで防ぐ。重複した中間行から最終行が重複保存されるか、表示値が変わるかは未確認であり、実測なしに数値誤りを断定しない。

GitHubの [PR commit変換](../../backend/plugins/github/tasks/pr_commit_convertor.go) はPR側だけをrepo/connectionで絞り、子のPR commit側には接続条件がない。この点は初稿の説明を訂正する。2026-11-24 14:15頃JSTに、repo_id=1057710129、PR側connection_id=10でread-only COUNTを実施し、現行結合76,004行、`prc.connection_id = pr.connection_id` を追加した結合14,075行（約5.40倍）を確認した。履歴75,758件とは観測時点が異なる。

[Workflow変換](../../backend/plugins/github/tasks/cicd_run_convertor.go) は対象repo/connectionを条件として保存済みデータを読む。[ApiExtractor](../../backend/helpers/pluginhelper/api/api_extractor.go) もparamsに一致するraw行を走査する。API取得が差分でも抽出・変換まで差分とは限らない。これらの条件を単純に「今回更新分のみ」へ変更すると、再計算・遅延更新・設定変更の反映を欠くため、今回の修正には含めない。

## 実装する変更

1. SonarQubeの結合を `i.issue_key = icb.issue_key AND i.connection_id = icb.connection_id` にする。
2. project条件を `i.project_key = ?` と修飾する。code blockにはproject_key列がなく、現行もissue側を指すため、修飾自体は可読性の改善で動作変更ではない。WHEREのproject条件によりLEFT JOINは実質INNER JOINとなる。対応課題が全くない行は引き続き変換しない。他接続だけに対応課題がある行も修正後は除外する。
3. 同じscope全体を再変換する既存動作、domain ID生成、保存方式は維持する。公開API・UI・スキーマ・認証情報・接続設定は変更しない。
4. GitHubの `pr_commit` / `pr_issue` / `pr_label` / `pr_comment` / `pr_review` / `review` / `issue_comment` / `issue_label` の各 `*_convertor.go`および `milestone_converter.go`（計9箇所）も今回の同じ実装PRに含める。親のgithub_idだけでなく親子のconnection_id一致をJOIN条件に追加し、子側の別接続行の混入を防ぐ。それぞれ同一キー・異なる接続の再現を作り、入力件数と出力内容を検証する。SonarQubeのissue_impactsは既に接続条件があり変更不要。その他の箇所や全量再変換最適化は今回に追加せず別計画とする。

## CIでの回帰検証

実際のコンバーターとDBのJOIN結果を通すテストを追加する。SQL文字列だけを照合するテストで済ませない。既存の `.github/workflows/test-e2e.yml` はGo変更PRで `make e2e-test-go-plugins` をMySQL/PostgreSQL双方で実行する。この経路を使い、新しいCI経路は追加しない。

既存 `sonarqube/e2e/issue_test.go` の2接続はキーもprojectも異なり再現に足りないため、同じissue_key/project_keyを異なる接続に持つCSV fixtureを追加する。GitHubも9箇所それぞれに同一親キー・異なる接続の子行を用意する。

入力件数は、各コンバーターが実際に使うFROM/JOIN/WHEREのclausesを、SELECTを含まないエクスポートされた小さな関数に切り出し、e2eから同じclausesを使う `db.Count(clauses...)` で検証する。テスト側に別のJOINを複製しない。既存e2ehelperの最終テーブル比較と併用し、upsertによって隠される重複入力も検出する。cursor側でのみSelectや必要なOrderbyを後から追加し、COUNT側には渡さない。これによりGORMによるCOUNT(icb.*)等への変換を避け、両DBで件数の一致を確認する。

- 単一接続の正常ケースは修正前と同じ出力。
- 2接続が同じissue_key/project_keyを持っても、対象接続の各code blockが1度ずつ変換される。最終upsertが重複を隠すため、最終件数だけでなく変換入力件数も検証する。
- 他接続だけに一致課題がある場合は取り込まれない。
- 同接続の別projectは除外、複数code blockは各1回、対応課題なしは変換されないことを維持する。GitHubの9箇所も同接続・対象repoの子行だけが各1回入力され、他接続の内容が出力に混入しないことを確認する。
- 再実行してもdomain ID・最終件数・内容が安定する。
- 既存SonarQubeテストをCIで実施。ローカルでCIの検証一式を重複実行しない。

## 配備と実機受入

1. 実装レビュー・CI成功後、承認されたforkイメージを作成しGitOpsで配備する。実行中の収集へのPod更新の影響を確認する。並列数2への変更とは別にSHA/digestを記録する。
2. testで2接続に同じ課題があるケースを確認し、その後stagingで既存の接続・projectを使って確認する。収集の開始や設定操作はCCIの通常UIからPlaywrightで行い、DB/APIで接続設定や収集状態を書き換えない。UIが順番待ちなら迂回起動しない。
3. 同じconnection/project（GitHubはrepo）について、修正後JOINの期待件数、実際の変換件数、所要時間、CPU・メモリ・再試行を記録する。修正前後のread-only `EXPLAIN` で使用インデックス・推定行数も保存する。SonarQubeの複合主キー `(connection_id, issue_key)` に対するアクセス改善は実行計画で確認し、行数減少と区別して記録する。並列数・データ増加・他処理負荷の条件も記録し、単純な前後時間差を全て本修正の効果としない。
4. 修正対象のSonarQube/GitHubについて通常UIからの収集完了と関連する表示の回帰を確認する。既存受入project 18801/19551の全指標の数値表示・ライフサイクル受入は別タスクとし、本修正の完了条件には含めない。
5. 異なる接続との結合による増幅がなくなり、期待入力件数・出力が一致、単一接続の回帰なし、通常UIで再収集できることを完了条件とする。「17分が必ず約3分になる」とは約束しない。

変更にDBマイグレーションは不要。異常時はGitOpsで直前イメージへ戻す。既存データは削除せず、過去に誤ったdomain行が作られたかは別途確認する。コード修正だけで既存の不要行が消えるとは扱わない。もしデータ補正が必要なら対象と復旧方法を別途レビューする。

## 後続の判断事項

- 全量再変換の最適化: 更新watermark、設定変更時の再計算、削除・再取得・失敗再開を満たす設計と件数の比較が必要。今回の限定修正を待たせない。
- 接続間の重複収集: 接続ごとに認証権限・取得範囲が違う可能性がある。repo名/project_keyの一致だけで統合しない。
- GraphQL再試行: EOF/502の発生区間と呼出サイズ・サーバー/プロキシ側状況を確認する。再試行を削ったりデータを省略して成功扱いにしない。
- GitOps #298: 同時実行数2は待機緩和策。testの並列負荷観測後、staging/releaseへ別途反映する。上記の行増幅や全量再変換を解消する修正ではない。

## 他ツールの横断確認（レビュー後の追加調査）

同じ配備revisionのJira/GitLab/Jenkins/SonarQube `tasks` 内の明示的SQL JOINと関連モデルの複合キー、WHERE条件を確認した。これは接続境界の結合条件の点検であり、ツール全体の無欠陥・性能・API認証の保証ではない。

| ツール | 接続をまたぐJOINの点検結果 | 今回の扱い |
| --- | --- | --- |
| Jira | issue/board、changelog、comment、label、relationship、worklog、sprint、commit、collector等の確認したJOINには接続一致条件あり | この種類の不足は未発見、製品変更しない |
| GitLab | MR commit/note/reviewer/label、issue labelのJOINには接続一致条件あり | この種類の不足は未発見、製品変更しない |
| Jenkins | `stage_convertor.go:74` はbuild_nameだけで結合し、build側のみconnectionで絞る。Stage/Build双方のキーにはconnection_idを含む。同名buildを異なる接続に持つ場合に他接続stageが混入し得る | 同種の接続境界修正として今回の実装PRに1箇所追加 |
| SonarQube | code blocksに欠落、issue impactsには接続一致条件あり | 前述の1箇所修正 |
| GitHub | 前述の9コンバーターで子側の接続条件が欠落 | 前述の9箇所修正 |

Jenkinsは `tjs.connection_id = tjb.connection_id` をJOINに追加する。通常jobとmulti-branch双方について、同じbuild名・stage IDを2接続に持つfixtureで対象接続だけの入力件数・出力を確認する。他接続だけにstageがあるケース、対応buildなしの除外も検証し、既存の単一接続動作を維持する。

stagingのread-only COUNTでは、Jenkins stages=0行、builds=3行、異接続JOIN行=0行だった。従ってコード上の条件欠落は確認できるが、現在のstaging遅延の原因としてJenkinsを挙げる根拠はない。実データ再現済みのSonarQube/GitHubと区別する。

今回の実装範囲は以上の計11箇所（SonarQube 1 / GitHub 9 / Jenkins 1）と対応回帰テスト。Jira/GitLabの予防的な書換えや、結合条件以外の改善は追加しない。UI受入・配備記録には対象3ツールを含め、Jenkinsに実機stageデータがない場合は合成fixtureのCI検証と実機未検証を明確に分ける。


## 再レビューで確認したGitHub milestoneの追加範囲

`milestone_converter.go:69` は `gm.milestone_id = gi.milestone_id` のみでJOINし、WHEREはmilestone側のrepo/connectionだけを絞っている。issue側にも `gi.connection_id = gm.connection_id` を要求する修正を、今回のGitHub9箇所に含める。

2026-11-24 18:16頃JST、stagingのrepo_id=1057710129、gm.connection_id=10でread-only COUNTを実施した結果、現行JOIN=0件、接続条件追加後=0件だった。この対象では行増幅を実測できておらず、PR commitの実測とは区別する。コード上の欠落は確認済みで、同じmilestone_id・issue IDを異なる接続に持つfixtureにより、対象接続のissueだけが各1回入力され、sprint_issues等の出力へ他接続のissueが混入しないことをMySQL/PostgreSQLのe2eで検証する。他接続だけにissueがある場合、単一接続、再実行時の安定性も確認する。


## 配備時の既存ドメイン行の収束確認（PR #11レビュー反映）

今回のJOIN修正は、新しい誤関連付けを止める。旧コードが作った行を無条件で削除するものではない。

`DataConverter.Execute` は出力IDを現在の実行接続Aで生成する一方、RawDataOriginを入力行からコピーする。このため別接続Bの子行を取り込んだ既存行は「AのID / Bのparams」となり得る。`BatchSaveDivider.ForType` の既存行削除は実行中のraw table/paramsに限定されるため、Aの再収集だけではBのparamsを持つ不要行が残り得る。また、入力0件・その出力型の生成0件ではForTypeが呼ばれず、削除も行われない。**全接続の再収集を開始しただけで収束済みと扱わない。**

### 配備前の確認

1. 同じrepo/project/jobを取得する全接続・scopeを一覧化し、有効/無効/削除済み、対応CCIプロジェクト、UIから再収集可能かを記録する。接続や権限は統合・変更しない。
2. [読み取り専用の出力キー見積SQL](2026-11-25-connection-join-key-estimate.sql) で、旧JOINが作るdistinctキーと接続一致条件を満たすキーを比較する。行増幅率と、消えるべき出力キー数を分けて記録する。SQLはstagingのMySQL用で、DB書換えはしない。
3. 対象ドメイン表ごとに、ID内の接続と `_raw_data_params` の接続を読み取り専用で比較する。GitHub/JenkinsのJSONキーは `ConnectionId`、SonarQubeは `connectionId` である。plugin/modelのID形式、複合キー、raw table、scopeを限定して比較し、空/不正JSON・解析不能なIDは0件へ丸めず別件数にする。結果はテーブル・接続・scope別の件数で保管し、認証情報やrawデータ本文をPRに掲載しない。
4. ID/paramsの一致だけでは正常とは断定できないため、旧JOINでのみ生成されるキーと現在のドメイン行の存在も突合する。GitHub milestoneはSprintIssueだけでなくSprint/BoardSprintにも出力するため、関連する全出力表を確認する。この移行監査は性能測定とは別の必須配備ゲートとする。

### 配備後の手順と完了条件

1. 修正版配備後、同じ対象を持つ**全ての有効接続のパイプラインを1回ずつ**、通常CCI UIからPlaywrightで再収集し、成功完了を確認する。スケジュール収集が同時に走る場合も実行IDを記録する。
2. 前項のドメイン監査を再実行し、接続不一致・旧JOIN由来の不要キーが0件で、解析不能行も未説明のまま残っていないことを確認する。0入力の接続、無効/削除済み接続・scope、UIから再実行できないものは明示して残件にする。
3. 旧キーとの差分に説明できない増減がないこと、正当な出力を欠落させていないこと、関連するUI表示の変化が想定範囲内であることを確認する。キー件数の減少をそのまま指標値の減少量とみなさない。
4. 残存する場合は本PRへ「配備済み・データ収束未完」と記録し、対象キー・件数・退避/復旧方法を含む別のデータ補正案をレビューに出す。今回は削除SQLを用意・実行せず、DB/APIで接続や収集状態を書き換えない。単に全接続再実行済みという理由で終了しない。

### staging事前見積（2026-11-25、配備前）

staging DB内に保存された全接続・repo/project/jobのtool行が対象であり、有効なCCIプロジェクトだけに限定した件数ではない。raw JOIN行数ではなく、接続/scopeとコンバーターの出力キー構成で重複排除し、そのキーに同接続の入力が1行でもあるかを比較した。現在のdomain行が実際に何件削除されるかを表すものではない。配備直前にはデータ増加と有効scopeを再確認する。

| 変換 | 旧キー | 接続一致キー | 旧JOINでのみ生成されるキー |
| --- | ---: | ---: | ---: |
| GitHub PR commit | 76,944 | 76,779 | 165 |
| GitHub PR issue | 0 | 0 | 0 |
| GitHub PR label | 1,402 | 1,397 | 5 |
| GitHub PR comment | 38,454 | 38,404 | 50 |
| GitHub PR review | 1,945 | 1,933 | 12 |
| GitHub reviewer | 733 | 732 | 1 |
| GitHub issue comment | 519 | 519 | 0 |
| GitHub issue label | 73 | 73 | 0 |
| GitHub milestone→issue | 0 | 0 | 0 |
| SonarQube code block | 120,906 | 120,906 | 0 |
| Jenkins stage | 0 | 0 | 0 |

GitHubの関連キーでは合計233件が旧JOINだけのキー。SonarQubeは入力行が増幅していてもdistinctキーの減少は0件であり、性能改善と表示値変化を区別する必要がある。この見積は同じキーに別接続の内容が上書きされる問題を数えないため、件数一致だけでは十分でなく内容の確認も必要である。

今回実施したのは事前の出力キー見積である。ドメインID/paramsの配備前監査は未実施で、配備前ゲートとして残す。修正版は未配備であり、全接続のUI再収集・配備後監査も受入の残件として引き継ぐ。
