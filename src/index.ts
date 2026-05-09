#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  doRequest,
  streamDownload,
  createSession,
  closeSession,
  listSessions,
  coerceObject,
  closeGlobalAgents,
  PKG_VERSION,
  type RequestSpec,
} from "./http.js";
import { clientCredentials, refreshToken, deviceStart, devicePoll, listCachedTokens, clearTokenCache } from "./oauth2.js";
import { toCurl } from "./curl.js";

// U5: proper response type — drop `as any`.
type McpTextContent = { type: "text"; text: string };
type McpResponse = { content: McpTextContent[]; isError?: boolean };

function textContent(data: unknown): McpResponse {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text", text }] };
}
function errContent(msg: string): McpResponse {
  return { content: [{ type: "text", text: msg }], isError: true };
}

const server = new McpServer({ name: "http-mcp", version: PKG_VERSION });

server.tool(
  "http",
  `HTTP client for LLMs. curl-equivalent + OAuth2 + sessions + retry.

Response bodies: textual types decoded with charset awareness; binary types base64-encoded; capped at HTTP_MAX_BODY (default 2 MiB) with body_truncated flag. status >= 400 sets MCP isError.

BODY SELECTION (choose one per request): json | form | body | body_base64.

AUTH: basic_auth | bearer | oauth2_* flows that cache tokens and can feed into 'bearer' of a subsequent request.

SESSIONS: cookie jars keyed by session id. Pass 'session' on request/get/post/etc to send and store cookies per domain. Manage with session_create / session_list / session_close. Caller-supplied ids are hashed; idle sessions evicted after HTTP_SESSION_TTL ms.

RETRY: retry={max, on_status, backoff_ms, max_backoff_ms}. Exponential backoff on transient 5xx by default.

SECURITY: SSRF guard blocks loopback / private networks unless HTTP_ALLOW_PRIVATE=1. reject_unauthorized=false ignored unless HTTP_ALLOW_INSECURE_TLS=1. download requires HTTP_DOWNLOAD_ROOT.

Actions:
- request / get / post / put / delete / patch / head: HTTP requests.
- download: GET + stream to output_path (must be under HTTP_DOWNLOAD_ROOT).
- as_curl: convert a request spec to a cURL command string. shell = bash | cmd | powershell. Output may include plaintext credentials; warning lines are prepended.
- session_create / session_close / session_list: cookie jar lifecycle.
- oauth2_client_credentials: machine-to-machine. Returns {access_token, expires_in, ...}. Caches by (token_url, client_id, secret_fingerprint, scope, audience).
- oauth2_refresh: refresh_token grant.
- oauth2_device_start: start device authorization flow.
- oauth2_device_poll: poll token endpoint. status=pending is NOT an error — caller should retry with the same device_code; status=expired/denied/error are isError.
- oauth2_list_tokens / oauth2_clear_cache.`,
  {
    action: z.enum([
      "request", "get", "post", "put", "delete", "patch", "head",
      "download", "as_curl",
      "session_create", "session_close", "session_list",
      "oauth2_client_credentials", "oauth2_refresh",
      "oauth2_device_start", "oauth2_device_poll",
      "oauth2_list_tokens", "oauth2_clear_cache",
    ]).describe("Action to perform"),
    // U1: every property gets a describe(). Each notes which actions consume it.
    url: z.string().optional().describe("request/get/post/put/delete/patch/head/download/as_curl: target URL (http/https)"),
    method: z.string().optional().describe("request: HTTP method override (default GET)"),
    headers: z.union([z.record(z.string()), z.string()]).optional()
      .describe("request/*/as_curl: additional request headers; values must be RFC 7230 valid"),
    query: z.union([
      z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))])),
      z.string(),
    ]).optional().describe("request/*/as_curl: query string params; arrays append multiple values"),
    body: z.string().optional().describe("request/*/as_curl: raw text body (mutually exclusive with json/form/body_base64)"),
    body_base64: z.string().optional().describe("request/*/as_curl: binary body, base64-encoded; defaults Content-Type to application/octet-stream"),
    json: z.unknown().optional().describe("request/*/as_curl: JSON body; sets Content-Type application/json"),
    form: z.union([z.record(z.string()), z.string()]).optional()
      .describe("request/*/as_curl: form-urlencoded body"),
    basic_auth: z.union([z.object({ user: z.string(), password: z.string() }), z.string()]).optional()
      .describe("request/*/as_curl: HTTP Basic credentials"),
    bearer: z.string().optional().describe("request/*/as_curl: Bearer token (printable ASCII only)"),
    timeout: z.number().optional().describe("request/*/download: per-hop timeout in ms (default HTTP_TIMEOUT, 30000). Total wall-clock budget = timeout × (max_redirects + 1)."),
    follow_redirects: z.boolean().optional().describe("request/*/as_curl: follow 3xx redirects (default true; cross-origin drops Authorization/Cookie)"),
    max_redirects: z.number().optional().describe("request/*: max redirect hops (default 5)"),
    reject_unauthorized: z.boolean().optional().describe("request/*: TLS verification toggle; false requires HTTP_ALLOW_INSECURE_TLS=1"),
    max_body_bytes: z.number().optional().describe("request/*: response body cap (default HTTP_MAX_BODY, 2 MiB). Also overrides HTTP_DOWNLOAD_MAX for the download action (which otherwise defaults to 1 GiB)."),
    session: z.string().optional().describe("request/*: session id for the cookie jar. Accepts either the server-generated id from session_create or a caller-supplied id (the latter is sha256-hashed before use)"),
    retry: z.union([z.object({
      max: z.number().optional(),
      on_status: z.array(z.number()).optional(),
      backoff_ms: z.number().optional(),
      max_backoff_ms: z.number().optional(),
    }), z.string()]).optional().describe("request/*: retry policy with exponential backoff (default on 502/503/504). Active only when max >= 1."),
    output_path: z.string().optional()
      .describe("download (REQUIRED): absolute destination path; must reside under HTTP_DOWNLOAD_ROOT; UNC paths rejected"),
    shell: z.enum(["bash", "cmd", "powershell"]).optional()
      .describe("as_curl: target shell syntax (default bash)"),
    session_id: z.string().optional()
      .describe("session_create/session_close: optional on session_create, REQUIRED for session_close. Caller-supplied id; the server hashes it (sha256, prefixed 'u_') before using it as the live key, so the raw id is never the cache key"),
    token_url: z.string().optional()
      .describe("oauth2_client_credentials/oauth2_refresh/oauth2_device_poll: token endpoint URL"),
    device_authorization_url: z.string().optional()
      .describe("oauth2_device_start: device authorization endpoint URL"),
    client_id: z.string().optional()
      .describe("oauth2_*: OAuth client id"),
    client_secret: z.string().optional()
      .describe("oauth2_client_credentials/oauth2_refresh/oauth2_device_poll: OAuth client secret (cache key uses sha256 fingerprint, not raw secret)"),
    scope: z.string().optional()
      .describe("oauth2_*: OAuth scope string"),
    audience: z.string().optional()
      .describe("oauth2_client_credentials/oauth2_device_start: optional audience parameter"),
    refresh_token: z.string().optional()
      .describe("oauth2_refresh: refresh_token to exchange"),
    device_code: z.string().optional()
      .describe("oauth2_device_poll: device_code from oauth2_device_start"),
    auth_method: z.enum(["basic", "form"]).optional()
      .describe("oauth2_client_credentials/oauth2_refresh: how to send client credentials. oauth2_client_credentials defaults to 'basic'. oauth2_refresh defaults to 'basic' only when client_secret is set, otherwise 'form' (public client)"),
    use_cache: z.boolean().optional()
      .describe("oauth2_client_credentials: reuse cached token if not yet expired (default true)"),
    max_wait_seconds: z.number().optional()
      .describe("oauth2_device_poll: max polling duration in seconds (default 120)"),
    initial_interval: z.number().optional()
      .describe("oauth2_device_poll: initial polling interval (in seconds; default 5). slow_down responses add 5 seconds each."),
    extra_params: z.union([z.record(z.string()), z.string()]).optional()
      .describe("oauth2_client_credentials/oauth2_device_start: extra form params merged into the token/device request. Not supported for oauth2_refresh."),
  },
  async (p): Promise<McpResponse> => {
    try {
      const httpActions = ["request", "get", "post", "put", "delete", "patch", "head"];
      if (httpActions.includes(p.action)) {
        if (!p.url) return errContent(`${p.action} requires 'url'`);
        const method = p.action === "request" ? (p.method ?? "GET") : p.action.toUpperCase();
        const spec: RequestSpec = { ...p, method, url: p.url };
        const res = await doRequest(spec);
        const resp = textContent(res);
        if (res.status >= 400) resp.isError = true;
        return resp;
      }

      if (p.action === "download") {
        if (!p.url) return errContent("download requires 'url'");
        if (!p.output_path) return errContent("download requires 'output_path'");
        const spec: RequestSpec & { output_path: string } = {
          ...p,
          method: "GET",
          url: p.url,
          output_path: p.output_path,
        };
        const r = await streamDownload(spec);
        const resp = textContent(r);
        if (r.status >= 400) resp.isError = true;
        return resp;
      }

      if (p.action === "as_curl") {
        if (!p.url) return errContent("as_curl requires 'url'");
        // U3: pick only RequestSpec keys so OAuth params can't leak into the curl output.
        const spec: RequestSpec = {
          url: p.url,
          method: p.method,
          headers: p.headers,
          query: p.query,
          body: p.body,
          body_base64: p.body_base64,
          json: p.json,
          form: p.form,
          basic_auth: p.basic_auth,
          bearer: p.bearer,
          timeout: p.timeout,
          follow_redirects: p.follow_redirects,
          max_redirects: p.max_redirects,
          reject_unauthorized: p.reject_unauthorized,
          max_body_bytes: p.max_body_bytes,
          session: p.session,
          retry: p.retry,
        };
        const cmd = toCurl(spec, p.shell ?? "bash");
        const hasCreds = /^# WARNING: this command contains plaintext/m.test(cmd);
        return textContent({
          command: cmd,
          shell: p.shell ?? "bash",
          ...(hasCreds ? { warning: "command output contains plaintext Authorization/Cookie credentials" } : {}),
        });
      }

      if (p.action === "session_create") return textContent(createSession(p.session_id));
      if (p.action === "session_close") {
        if (!p.session_id) return errContent("session_close requires 'session_id'");
        return textContent(closeSession(p.session_id));
      }
      if (p.action === "session_list") {
        // B5: snapshot once — listSessions() runs eviction and could differ between calls.
        const s = listSessions();
        return textContent({ count: s.length, sessions: s });
      }

      if (p.action === "oauth2_client_credentials") {
        if (!p.token_url || !p.client_id || !p.client_secret) return errContent("oauth2_client_credentials requires token_url, client_id, client_secret");
        const t = await clientCredentials({
          token_url: p.token_url, client_id: p.client_id, client_secret: p.client_secret,
          scope: p.scope, audience: p.audience,
          auth_method: p.auth_method, extra_params: coerceObject<Record<string, string>>(p.extra_params), use_cache: p.use_cache,
        });
        return textContent({
          access_token: t.access_token, token_type: t.token_type ?? "Bearer",
          expires_in_s: Math.max(0, Math.round((t.expires_at - Date.now()) / 1000)),
          scope: t.scope, refresh_token: t.refresh_token,
        });
      }
      if (p.action === "oauth2_refresh") {
        if (!p.token_url || !p.client_id || !p.refresh_token) return errContent("oauth2_refresh requires token_url, client_id, refresh_token");
        const t = await refreshToken({
          token_url: p.token_url, client_id: p.client_id, client_secret: p.client_secret,
          refresh_token: p.refresh_token, scope: p.scope, auth_method: p.auth_method,
        });
        return textContent({
          access_token: t.access_token, token_type: t.token_type ?? "Bearer",
          expires_in_s: Math.max(0, Math.round((t.expires_at - Date.now()) / 1000)),
          scope: t.scope, refresh_token: t.refresh_token,
        });
      }
      if (p.action === "oauth2_device_start") {
        if (!p.device_authorization_url || !p.client_id) return errContent("oauth2_device_start requires device_authorization_url, client_id");
        return textContent(await deviceStart({
          device_authorization_url: p.device_authorization_url,
          client_id: p.client_id, scope: p.scope, audience: p.audience,
          extra_params: coerceObject<Record<string, string>>(p.extra_params),
        }));
      }
      if (p.action === "oauth2_device_poll") {
        if (!p.token_url || !p.client_id || !p.device_code) return errContent("oauth2_device_poll requires token_url, client_id, device_code");
        const r = await devicePoll({
          token_url: p.token_url, client_id: p.client_id, client_secret: p.client_secret,
          device_code: p.device_code,
          max_wait_seconds: p.max_wait_seconds, initial_interval: p.initial_interval,
        });
        if (r.status === "authorized") {
          return textContent({
            status: "authorized",
            access_token: r.token.access_token,
            expires_in_s: Math.max(0, Math.round((r.token.expires_at - Date.now()) / 1000)),
            scope: r.token.scope, refresh_token: r.token.refresh_token,
          });
        }
        const resp = textContent(r);
        if (r.status === "denied" || r.status === "expired" || r.status === "error") resp.isError = true;
        return resp;
      }
      if (p.action === "oauth2_list_tokens") return textContent({ tokens: listCachedTokens() });
      if (p.action === "oauth2_clear_cache") return textContent(clearTokenCache());

      return errContent(`unknown action: ${p.action}`);
    } catch (err: unknown) {
      const e = err as { message?: string; stack?: string; cause?: { message?: string }; oauth_error?: unknown } | undefined;
      // U5: log full diagnostic detail (cause, stack) to stderr; keep user-facing
      // message minimal to avoid leaking internal error chains via the LLM channel.
      if (e?.cause?.message || e?.stack) {
        process.stderr.write(`[http-mcp] error: ${e?.stack ?? e?.message ?? String(err)}${e?.cause?.message ? ` (cause: ${e.cause.message})` : ""}\n`);
      }
      // U6: surface structured oauth_error if present
      if (e?.oauth_error) {
        return errContent(`HTTP error: ${e?.message ?? String(err)}\noauth_error: ${JSON.stringify(e.oauth_error)}`);
      }
      return errContent(`HTTP error: ${e?.message ?? String(err)}`);
    }
  },
);

async function shutdown(reason: string): Promise<void> {
  process.stderr.write(`[http-mcp] shutting down: ${reason}\n`);
  try { await closeGlobalAgents(); } catch (e) {
    process.stderr.write(`[http-mcp] agent close failed: ${(e as Error).message}\n`);
  }
  try { await server.close(); } catch (e) {
    process.stderr.write(`[http-mcp] server close failed: ${(e as Error).message}\n`);
  }
}

// B19: graceful shutdown
process.on("SIGTERM", () => { void shutdown("SIGTERM").finally(() => process.exit(0)); });
process.on("SIGINT", () => { void shutdown("SIGINT").finally(() => process.exit(0)); });
// U10
process.on("unhandledRejection", (err) => {
  process.stderr.write(`[http-mcp] unhandledRejection: ${(err as Error)?.stack ?? String(err)}\n`);
});
process.on("uncaughtException", (err) => {
  process.stderr.write(`[http-mcp] uncaughtException: ${err.stack ?? String(err)}\n`);
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => { console.error("Fatal:", err); process.exit(1); });
