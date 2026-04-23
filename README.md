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

v0.2 では**実用で詰まる所**を埋めた: OAuth2 の主要 3 フロー (client_credentials / refresh / device flow) をトークンキャッシュ付きで、セッションクッキー (tough-cookie) で複数リクエストを跨ぐ状態保持、5xx 指数バックオフリトライ、任意リクエストを cURL コマンド文字列に変換。

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
| `oauth2_device_poll` | 認可待ちをポーリング (`max_wait_seconds` デフォルト 120、`initial_interval` 秒刻み)。`authorized` / `pending` / `expired` / `denied` |
| `oauth2_list_tokens` | キャッシュ済みトークンの一覧（expires_in_s 付き） |
| `oauth2_clear_cache` | トークンキャッシュ全消去 |

トークンは `(token_url, client_id, scope)` でキャッシュ、有効期限の 30 秒前まで再利用。取得した `access_token` を次のリクエストで `bearer: ...` に渡せば認証済みリクエストが打てる。

### リトライ

`retry: {max, on_status, backoff_ms, max_backoff_ms}` を渡すと指数バックオフ (`min(max_backoff_ms, backoff_ms * 2^n)`) でリトライ。デフォルト `on_status: [502, 503, 504]`。レスポンスに `attempts` と `retried_on[]` が入る。

## インストール

```bash
git clone https://github.com/cUDGk/http-mcp.git
cd http-mcp && npm install && npm run build
```

## 使い方

### Claude Code に登録

```bash
claude mcp add http -- node C:/Users/user/Desktop/http-mcp/dist/index.js
```

### 環境変数

| 変数 | デフォルト | 用途 |
|---|---|---|
| `HTTP_TIMEOUT` | `30000` | 単一リクエストのタイムアウト (ms) |
| `HTTP_MAX_BODY` | `2097152` | レスポンスボディの最大バイト数 (デフォルト 2 MiB) |
| `HTTP_USER_AGENT` | `http-mcp/0.1` | 既定の User-Agent |

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

バイナリダウンロード:

```json
{"action": "download", "url": "https://example.com/asset.zip",
 "output_path": "C:/tmp/asset.zip"}
```

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

`reject_unauthorized: false` は**自己署名証明書を無条件で受け入れる**。MITM リスクがあるので本番 API には使わない。`basic_auth` / `bearer` は**ログには残らない**が、MCP の上位ログに残る可能性はあるので、本物の認証情報を安易に LLM プロンプトに載せない。

## Attribution

- [undici](https://github.com/nodejs/undici) — Node.js の HTTP/1.1 クライアント
- [Model Context Protocol](https://modelcontextprotocol.io/) — 仕様・SDK

## ライセンス

MIT License © 2026 cUDGk — 詳細は [LICENSE](LICENSE) を参照。
