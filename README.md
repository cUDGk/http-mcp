<div align="center">

# http-mcp

### HTTP リクエストを LLM から安全に叩く MCP サーバー

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat&logo=typescript&logoColor=white)](src/index.ts)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A520-339933?style=flat&logo=node.js&logoColor=white)](package.json)
[![undici](https://img.shields.io/badge/undici-7-8A2BE2?style=flat)](https://github.com/nodejs/undici)
[![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF?style=flat)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

**API テスト・ヘッダ確認・Basic/Bearer 認証・リダイレクト追跡を一撃で。**

---

</div>

## 概要

curl 相当の機能を **undici 直叩き**で提供する。レスポンスボディは content-type に応じて**テキスト decode か base64 encode を自動選択**し、2 MiB で自動 truncate。ヘッダは全て小文字化して返す。

## 特徴

| アクション | 用途 |
|---|---|
| `request` | フル機能（`method` / `headers` / `body` / `json` / `form` / `query` / 認証 / リダイレクト制御） |
| `get` / `post` / `put` / `delete` / `patch` / `head` | `method` だけ固定したショートカット |
| `download` | GET してレスポンスを `output_path` に書き出す。バイナリも OK |

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

Form + Query + Basic auth:

```json
{"action": "request", "url": "https://httpbin.org/post",
 "method": "POST",
 "query": {"debug": true},
 "form": {"k": "v"},
 "basic_auth": {"user": "u", "password": "p"}}
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
