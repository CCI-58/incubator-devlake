# 収集時間の短縮とSonarQube接続境界の修正計画

## レビュー対象

stagingの収集が長時間待機する原因を調査した結果、直列実行に加え、SonarQubeのSQL結合条件不足による処理行増幅を確認した。まずこの不具合を独立した実装PRで修正する。承認前に製品コード、DB、稼働設定は変更しない。

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

GitHubの [PR commit変換](../../backend/plugins/github/tasks/pr_commit_convertor.go)、[Workflow変換](../../backend/plugins/github/tasks/cicd_run_convertor.go) は対象repo/connectionを条件として保存済みデータを読む。[ApiExtractor](../../backend/helpers/pluginhelper/api/api_extractor.go) もparamsに一致するraw行を走査する。API取得が差分でも抽出・変換まで差分とは限らない。これらの条件を単純に「今回更新分のみ」へ変更すると、再計算・遅延更新・設定変更の反映を欠くため、今回の修正には含めない。

## 実装する変更

1. SonarQubeの結合を `i.issue_key = icb.issue_key AND i.connection_id = icb.connection_id` にする。
2. project条件を `i.project_key = ?` と修飾し、code blockとissueの両方が同じ接続・対象projectに属することを明確にする。
3. 同じscope全体を再変換する既存動作、domain ID生成、保存方式は維持する。公開API・UI・スキーマ・認証情報・接続設定は変更しない。
4. 関連するSonarQubeコンバーターとGitHub PR commitの結合条件も読み取りで点検する。同種の欠落があれば具体的な再現と影響を記録し、実装範囲をレビューで明示してから取り込む。無関係な高速化は同梱しない。

## CIでの回帰検証

実際のコンバーターとDBのJOIN結果を通すテストを追加する。SQL文字列だけを照合するテストで済ませない。既存のテスト基盤・CI対象を実装時に確認し、必要なら当該テストを実行するCI経路を追加する。

- 単一接続の正常ケースは修正前と同じ出力。
- 2接続が同じissue_key/project_keyを持っても、対象接続の各code blockが1度ずつ変換される。最終upsertが重複を隠すため、最終件数だけでなく変換入力件数も検証する。
- 他接続だけに一致課題がある場合は取り込まれない。
- 同接続の別project、複数code block、対応課題なしを含め、対象範囲と正しい全件変換を維持する。
- 再実行してもdomain ID・最終件数・内容が安定する。
- 既存SonarQubeテストをCIで実施。ローカルでCIの検証一式を重複実行しない。

## 配備と実機受入

1. 実装レビュー・CI成功後、承認されたforkイメージを作成しGitOpsで配備する。実行中の収集へのPod更新の影響を確認する。並列数2への変更とは別にSHA/digestを記録する。
2. testで2接続に同じ課題があるケースを確認し、その後stagingで既存の接続・projectを使って確認する。収集の開始や設定操作はCCIの通常UIからPlaywrightで行い、DB/APIで接続設定や収集状態を書き換えない。UIが順番待ちなら迂回起動しない。
3. 同じconnection/projectについて、修正後JOINの期待件数、実際の変換件数、所要時間、CPU・メモリ・再試行を記録する。並列数・データ増加・他処理負荷の条件も記録し、単純な前後時間差を全て本修正の効果としない。
4. 対応するSonarQube指標をUIで確認する。性能改善だけで指標表示全体の受入完了とはしない。stagingの既存受入project 18801/19551についても収集状態と取得元の対応を確認し、未接続の指標を成功扱いにしない。
5. 異なる接続との結合による増幅がなくなり、期待入力件数・出力が一致、単一接続の回帰なし、通常UIで再収集できることを完了条件とする。「17分が必ず約3分になる」とは約束しない。

変更にDBマイグレーションは不要。異常時はGitOpsで直前イメージへ戻す。既存データは削除せず、過去に誤ったdomain行が作られたかは別途確認する。コード修正だけで既存の不要行が消えるとは扱わない。もしデータ補正が必要なら対象と復旧方法を別途レビューする。

## 後続の判断事項

- 全量再変換の最適化: 更新watermark、設定変更時の再計算、削除・再取得・失敗再開を満たす設計と件数の比較が必要。今回の限定修正を待たせない。
- 接続間の重複収集: 接続ごとに認証権限・取得範囲が違う可能性がある。repo名/project_keyの一致だけで統合しない。
- GraphQL再試行: EOF/502の発生区間と呼出サイズ・サーバー/プロキシ側状況を確認する。再試行を削ったりデータを省略して成功扱いにしない。
- GitOps #298: 同時実行数2は待機緩和策。testの並列負荷観測後、staging/releaseへ別途反映する。上記の行増幅や全量再変換を解消する修正ではない。
