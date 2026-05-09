<div align="center">

# http-mcp

### HTTP リクエストを LLM から安全に叩く MCP サーバー

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat&logo=typescript&logoColor=white)](src/index.ts)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A520-339933?style=flat&logo=node.js&logoColor=white)](package.json)
[![undici](https://img.shields.io/badge/undici-7-8A2BE2?style=flat)](https://github.com/nodejs/undici)
[![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF?style=flat)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

**API テスト・OAuth2 フル対応・セッションクッキー・リトライ・curl コマンド生成を一撃で。**

---

</div>

## 概要

curl 相当の機能を **undici 直叩き**で提供する。レスポンスボディは content-type に応じて**テキスト decode か base64 encode を自動選択**し、2 MiB で自動 truncate。ヘッダは全て小文字化して返す。

v0.3 では**実用で詰まる所**を埋めた: OAuth2 の主要 3 フロー (client_credentials / refresh / device flow) をトークンキャッシュ付きで、セッションクッキー (tough-cookie) で複数リクエストを跨ぐ状態保持、5xx 指数バックオフリトライ、任意リクエストを cURL コマンド文字列に変換。

## 特徴

### HTTP リクエスト

| アクション | 用途 |
|---|---|
| `request` | フル機能（`method` / `headers` / `body` / `json` / `form` / `query` / 認証 / リダイレクト制御 / retry / session） |
| `get` / `post` / `put` / `delete` / `patch` / `head` | `method` だけ固定したショートカット |
| `download` | GET してレスポンスを `output_path` に書き出す。バイナリも OK |
| `as_curl` | リクエスト仕様から cURL コマンド文字列を生成 (`shell: bash | cmd | powershell`) |

### セッション (Cookie jar)

| アクション | 用途 |
|---|---|
| `session_create` | セッションを作成、ID を返す (`session_id` オプション指定可) |
| `session_close` | セッション破棄 |
| `session_list` | 現在アクティブなセッション一覧 |

リクエスト系アクションで `session: <id>` を指定すると、そのセッションの Cookie jar を使って送受信する (tough-cookie ベース)。

### OAuth2

| アクション | 用途 |
|---|---|
| `oauth2_client_credentials` | machine-to-machine (M2M) フロー。`basic` / `form` 認証方式対応、scope/audience 付与可、デフォルトで token キャッシュ (`use_cache: false` で無効化) |
| `oauth2_refresh` | refresh_token フロー |
| `oauth2_device_start` | デバイス認可フロー開始。`device_code` / `user_code` / `verification_uri` / `interval` を返す |
| `oauth2_device_poll` | 認可待ちをポーリング (`max_wait_seconds` デフォルト 120、`initial_interval` 秒刻み)。status: `authorized` / `pending` / `expired` / `denied` / `error`。`pending` は isError ではない（同じ device_code で再呼び出し）、`expired` / `denied` / `error` は isError |
| `oauth2_list_tokens` | キャッシュ済みトークンの一覧（expires_in_s 付き） |
| `oauth2_clear_cache` | トークンキャッシュ全消去 |

トークンは `(flow, token_url, client_id, secret_fingerprint, scope, audience)` でキャッシュ、有効期限の 30 秒前まで再利用。取得した `access_token` を次のリクエストで `bearer: ...` に渡せば認証済みリクエストが打てる。

### リトライ

`retry: {max, on_status, backoff_ms, max_backoff_ms}` を渡すと指数バックオフ (`min(max_backoff_ms, backoff_ms * 2^n)`) でリトライ。デフォルト `on_status: [502, 503, 504]`。レスポンスに `attempts` と `retried_on[]` が入る。

## インストール

```bash
git clone https://github.com/cUDGk/http-mcp.git
cd http-mcp && npm install && npm run build
```

## 使い方

### Claude Code に登録

`<install-dir>` を `git clone` した先の絶対パスに置き換える。

```bash
# POSIX
claude mcp add http -- node <install-dir>/dist/index.js
# Windows (PowerShell / cmd)
claude mcp add http -- node C:\path\to\http-mcp\dist\index.js
```

### 環境変数

| 変数 | デフォルト | 用途 |
|---|---|---|
| `HTTP_TIMEOUT` | `30000` | **per-hop** タイムアウト (ms)。各 redirect hop ごとに独立して適用される。**total wall-clock budget = `HTTP_TIMEOUT` × (`max_redirects` + 1)** なので、 redirect 上限を上げると全体のタイムアウトも比例して伸びる |
| `HTTP_MAX_BODY` | `2097152` | レスポンスボディの最大バイト数 (デフォルト 2 MiB) |
| `HTTP_USER_AGENT` | `http-mcp/<package version>` | 既定の User-Agent (package.json の version を反映) |
| `HTTP_ALLOW_PRIVATE` | (未設定) | `1` で SSRF ガード無効化（loopback / 10/8 / 172.16/12 / 192.168/16 / 169.254/16 / IPv6 ULA / `localhost` / `*.internal` 等を許可） |
| `HTTP_ALLOW_INSECURE_TLS` | (未設定) | `1` で `reject_unauthorized: false` を尊重。未設定の場合は警告して TLS 検証を強制 |
| `HTTP_ALLOW_INSECURE_OAUTH` | (未設定) | `1` で OAuth2 token_url / device_authorization_url の `http://` 接続を許可（デフォルトは HTTPS のみ。クライアントシークレット流出を防ぐためテスト用途以外では未設定推奨） |
| `HTTP_DOWNLOAD_ROOT` | (未設定) | `download` の出力先許可ディレクトリ。**未設定だと `download` は失敗**。`output_path` はこの配下のみ許可、UNC パス (`\\?\`, `\\server\`) は拒否 |
| `HTTP_DOWNLOAD_MAX` | `1073741824` | `download` の最大バイト数 (デフォルト 1 GiB) — 通常レスポンスの `HTTP_MAX_BODY` とは別 |
| `HTTP_SESSION_TTL` | `3600000` | セッションの idle TTL (ms)。これを過ぎたセッションは自動 evict |
| `HTTP_SESSION_MAX` | `256` | 同時に保持できるセッション数の上限 |

### 呼び出し例

JSON POST + Bearer 認証:

```json
{"action": "post", "url": "https://api.example.com/v1/items",
 "bearer": "sk-...", "json": {"name": "hello"}}
```

OAuth2 client_credentials で取ったトークンで API を叩く:

```json
{"action": "oauth2_client_credentials",
 "token_url": "https://auth.example.com/oauth/token",
 "client_id": "...", "client_secret": "...",
 "scope": "read:users"}
```
レスポンスの `access_token` を次の呼び出しの `bearer` に渡す:
```json
{"action": "get", "url": "https://api.example.com/users",
 "bearer": "<access_token>"}
```

OAuth2 デバイス認可フロー (GitHub CLI / Google OAuth 等):

```json
{"action": "oauth2_device_start",
 "device_authorization_url": "https://github.com/login/device/code",
 "client_id": "Iv1.xxx",
 "scope": "repo"}
```
`user_code` をユーザーに提示し、ブラウザで認証してもらってから:
```json
{"action": "oauth2_device_poll",
 "token_url": "https://github.com/login/oauth/access_token",
 "client_id": "Iv1.xxx",
 "device_code": "<device_code>",
 "max_wait_seconds": 180}
```

Cookie jar を使った複数リクエストの状態保持:

```json
{"action": "session_create"}
// → {"id": "s_..."}
{"action": "post", "session": "s_...", "url": "https://example.com/login", "form": {"u":"u","p":"p"}}
{"action": "get",  "session": "s_...", "url": "https://example.com/dashboard"}
```

5xx に指数バックオフでリトライ:

```json
{"action": "get", "url": "https://flaky.example.com/api",
 "retry": {"max": 3, "on_status": [502, 503, 504],
           "backoff_ms": 500, "max_backoff_ms": 10000}}
```

リクエスト仕様を cURL コマンドに変換してターミナルで再現:

```json
{"action": "as_curl", "shell": "bash",
 "url": "https://api.example.com/v1/items",
 "method": "POST", "bearer": "sk-abc",
 "json": {"name": "hello"}}
```

バイナリダウンロード（要 `HTTP_DOWNLOAD_ROOT`、`output_path` はその配下に限る、UNC 不可）:

```bash
# 例: HTTP_DOWNLOAD_ROOT=C:/tmp  をセットしてから
```
```json
{"action": "download", "url": "https://example.com/asset.zip",
 "output_path": "C:/tmp/asset.zip"}
```

レスポンスはストリーミングでディスクに直書きされる (通常レスポンスの 2 MiB 上限と分離、デフォルト `HTTP_DOWNLOAD_MAX=1 GiB`)。

## レスポンス形式

```json
{
  "url": "https://...",
  "status": 200,
  "headers": {"content-type": "application/json; charset=utf-8", ...},
  "content_type": "application/json; charset=utf-8",
  "content_length": 1234,
  "body_encoding": "text",
  "body": "{\"ok\": true}",
  "body_truncated": false,
  "redirects": [],
  "duration_ms": 123
}
```

`status >= 400` は MCP 応答で `isError: true` が立つ。

## セキュリティ注意

- **SSRF ガード**: `localhost` / `127.0.0.0/8` / `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` / `169.254.0.0/16` / IPv6 ULA・link-local・loopback / `*.internal` への接続をデフォルトで拒否。DNS 解決後の IP も再検証。社内ネットワーク向けには `HTTP_ALLOW_PRIVATE=1` を明示的に設定。
- **リダイレクト再検証**: 各 3xx hop ごとに SSRF ガードを再評価。クロスオリジン redirect では `Authorization` / `Cookie` / `Proxy-Authorization` を破棄。
- **ヘッダーインジェクション**: ヘッダー名・値を RFC 7230 でバリデート。`bearer` は printable ASCII のみ。
- **TLS**: `reject_unauthorized: false` は `HTTP_ALLOW_INSECURE_TLS=1` がない限り無視 (警告ログ出力)。
- **セッション**: caller が指定した `session_id` は SHA-256 でハッシュ化された値を内部で使用 (cross-leak 防止)。idle TTL `HTTP_SESSION_TTL` ms (デフォルト 1 時間) で自動 evict。
- **OAuth トークンキャッシュ**: cache key に `client_secret` の sha256 fingerprint を含めるため、同じ `client_id` でも secret が違えばキャッシュ衝突しない。
- **`as_curl` 出力**: `Authorization` / `Cookie` を含むコマンドは平文で出力される。LLM 経由で他者に共有する場合は要注意 (出力に `# WARNING: ...` を自動で前置)。
- **download**: `HTTP_DOWNLOAD_ROOT` を設定しないと使えない。`output_path` はそれ配下に限定、UNC パスは拒否。
- 上記に加え、`basic_auth` / `bearer` は**サーバ自身のログには残らない**が、MCP の上位ログに残る可能性はあるので、本物の認証情報を安易に LLM プロンプトに載せない。

## v0.3.1 修正

R4 final-pass: edge-case fixes on top of v0.3.0.

- **セキュリティ**: SSRF guard を `::ffff:127.0.0.1` 等の IPv4-mapped IPv6（dotted / hex 両形式）と `::` (unspecified) にも拡張 (S1 / S2)、OAuth2 全フローで token_url / device_authorization_url の HTTPS を必須化 — `HTTP_ALLOW_INSECURE_OAUTH=1` で明示的に opt-out 可 (S3)、クロスオリジン redirect で caller 由来の `Cookie` ヘッダも破棄するよう拡張 (S4)、`basic_auth.user` に `:` を含む値を拒否 (S5)、`download` の `output_path` で UNC に加え Windows device-namespace path (`\\.\`) も拒否 (S6)、OAuth トークンキャッシュに 512 entry 上限と expired-first eviction を追加 (S7)
- **バグ**: redirect の body drain で `destroy` が無いストリームを iterate-to-completion でフォールバック (B1)、`hop === maxRedirects` 時に redirect レスポンスを最終応答として返してしまう問題を修正（drain して exceeded-max-redirects を throw）(B2)、`max_body` 到達時の abort と timeout abort を別フラグで track して `aborted_reason` を正しくラベリング (B3)、`oauth2_refresh` のキャッシュキーに `scope` と refresh_token fingerprint を追加（rotation 後に古い token を返す問題を修正）(B4)、`oauth2_device_poll` で 200 + access_token 無 + error 無の応答を `unexpected_200` として明示終了（無限ソフトループ防止）(B5)、`Content-Type: ...; charset=utf-8` 明示時にも UTF-8 BOM を strip (B6)、file sink で `received = cap` を await 完了前に立てていたのを修正 (B7)
- **UX/Schema/Docs**: `timeout` / `max_body_bytes` / `retry` / `initial_interval` / `session_id` / `extra_params` の describe を整備 (U1-U6)、README env-var table に `HTTP_USER_AGENT` / `HTTP_ALLOW_INSECURE_OAUTH` を追加 (U7)、v0.3.1 changelog 追加 + version 同期 (U8)、stale な `v0.2 では` 文言を v0.3 に更新 (U9)、`HTTP_TIMEOUT` を per-hop と明記し total wall-clock = `timeout × (max_redirects + 1)` を README にも反映 (U10)、`oauth2.ts` の `makeError` 内 catch swallow に理由コメントを追加 (U11)、curl bash の binary body を `echo` から `printf '%s'` へ（trailing newline 防止）(U12)、PowerShell binary の `[Convert]::FromBase64String(...) | curl` がバイト忠実でない警告と temp-file 代替を出力に追加 (U13)

## v0.3.0 修正

セキュリティ・バグ・UX 全方位アップデート。サーバ名を `http-mcp` に統一。

- **セキュリティ**: SSRF ガード (S1)、redirect 毎の再検証 + クロスオリジン認証ヘッダ破棄 (S2)、ヘッダーインジェクション防御 (S3)、TLS 検証バイパスの env ゲート化 (S4)、`download` の path allowlist (S5)、session id ハッシュ + idle TTL evict (S6)、OAuth キャッシュキーに secret fingerprint (S7)、`as_curl` 認証情報警告 (S8)
- **バグ**: グローバル `Agent` の再利用 (B1)、独自 redirect → `redirects[]` を実値で出力 (B3)、timeout 時に `aborted_reason: "timeout"` を返す (B4)、上限到達時に socket クリーンアップ (B5)、charset / BOM 対応の本文デコード (B6)、`TEXTUAL` regex の修正 (B7)、`Buffer.from` の死コード除去 (B8)、Set-Cookie を redirect 後の最終 URL で保存 (B9)、リトライ末尾の sleep 削除 (B10)、`coerceObject` JSON エラー伝播 (B11)、OAuth `body_encoding=base64` 対応 (B12)、`expires_in - 30` 負値ガード (B13)、device poll の HTTP ステータス分離 (B14)、token レスポンス zod バリデーション (B15)、`body_base64` の Content-Type デフォルト (B16)、`noUncheckedIndexedAccess` 有効化 (B17)、env 数値バリデーション (B18)、SIGTERM/SIGINT 経由のグレースフル shutdown (B19)
- **UX**: 全プロパティに describe (U1)、`download` ストリーミング書き出し (U2/U3)、README の path / env / 警告整備 (U4)、`as McpResponse` 型化 (U5)、OAuth 構造化エラー (U6)、binary body の curl 警告整形 (U7)、cmd 引用注意書き (U8)、tough-cookie swallow コメント (U9)、unhandledRejection ロガー (U10)

## v0.2.1 修正

一部の MCP クライアント (Claude Code の LLM ツール使用パス等) が**オブジェクト引数を JSON 文字列化してからサーバーに渡す**挙動があり、`json` パラメータが二重エンコードされて送信先 (例: Discord Webhook) が「dictionary が期待された」と 400 を返す問題があった。

修正内容:
- `headers` / `form` / `basic_auth` / `query` / `retry` / `extra_params` の zod schema を `z.union([<本来の型>, z.string()])` に緩和
- `coerceObject()` ヘルパを追加し、文字列で届いた場合は `JSON.parse` で object に戻してから使用
- `json` パラメータは文字列を受けたら先に `JSON.parse` して、本来のボディ形状で再シリアライズ (二重エンコード防止)

## Attribution

- [undici](https://github.com/nodejs/undici) — Node.js の HTTP/1.1 クライアント
- [Model Context Protocol](https://modelcontextprotocol.io/) — 仕様・SDK

## ライセンス

MIT License © 2026 cUDGk — 詳細は [LICENSE](LICENSE) を参照。
