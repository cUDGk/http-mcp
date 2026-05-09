#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Buffer } from "node:buffer";
import { writeFileSync } from "node:fs";
import { z } from "zod";
import { doRequest, createSession, closeSession, listSessions, coerceObject, type RequestSpec } from "./http.js";
import { clientCredentials, refreshToken, deviceStart, devicePoll, listCachedTokens, clearTokenCache } from "./oauth2.js";
import { toCurl } from "./curl.js";

function textContent(data: unknown) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text" as const, text }] };
}
function errContent(msg: string) {
  return { content: [{ type: "text" as const, text: msg }], isError: true };
}

const server = new McpServer({ name: "http", version: "0.2.1" });

server.tool(
  "http",
  `HTTP client for LLMs. curl-equivalent + OAuth2 + sessions + retry.

Response bodies: textual types decoded as UTF-8; binary types base64-encoded; capped at HTTP_MAX_BODY (default 2 MiB) with body_truncated flag. status >= 400 sets MCP isError.

BODY SELECTION (choose one per request): json | form | body | body_base64.

AUTH: basic_auth | bearer | oauth2_* flows that cache tokens and can feed into 'bearer' of a subsequent request.

SESSIONS: cookie jars keyed by session id. Pass 'session' on request/get/post/etc to send and store cookies per domain. Manage with session_create / session_list / session_close.

RETRY: retry={max, on_status, backoff_ms, max_backoff_ms}. Exponential backoff on transient 5xx by default.

Actions:
- request / get / post / put / delete / patch / head: HTTP requests.
- download: GET + write to output_path.
- as_curl: convert a request spec to a cURL command string. shell = bash | cmd | powershell.
- session_create / session_close / session_list: cookie jar lifecycle.
- oauth2_client_credentials: machine-to-machine. Returns {access_token, expires_in, ...}. Caches by (token_url, client_id, scope). Subsequent calls reuse until 30s before expiry.
- oauth2_refresh: refresh_token grant.
- oauth2_device_start: start device authorization flow. Returns {device_code, user_code, verification_uri, expires_in, interval}.
- oauth2_device_poll: poll token endpoint until authorized / expired / denied. Blocks up to max_wait_seconds (default 120). Returns {status: authorized|pending|expired|denied, ...}.
- oauth2_list_tokens / oauth2_clear_cache.`,
  {
    action: z.enum([
      "request", "get", "post", "put", "delete", "patch", "head",
      "download", "as_curl",
      "session_create", "session_close", "session_list",
      "oauth2_client_credentials", "oauth2_refresh",
      "oauth2_device_start", "oauth2_device_poll",
      "oauth2_list_tokens", "oauth2_clear_cache",
    ]).describe("Action"),
    // request shape
    url: z.string().optional(),
    method: z.string().optional(),
    // object-typed args accept a JSON-encoded string too — some MCP clients
    // serialize objects/arrays before sending, and we unwrap at runtime.
    headers: z.union([z.record(z.string()), z.string()]).optional(),
    query: z.union([
      z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))])),
      z.string(),
    ]).optional(),
    body: z.string().optional(),
    body_base64: z.string().optional(),
    json: z.unknown().optional(),
    form: z.union([z.record(z.string()), z.string()]).optional(),
    basic_auth: z.union([z.object({ user: z.string(), password: z.string() }), z.string()]).optional(),
    bearer: z.string().optional(),
    timeout: z.number().optional(),
    follow_redirects: z.boolean().optional(),
    max_redirects: z.number().optional(),
    reject_unauthorized: z.boolean().optional(),
    max_body_bytes: z.number().optional(),
    session: z.string().optional().describe("Session id to send/store cookies"),
    retry: z.union([z.object({
      max: z.number().optional(),
      on_status: z.array(z.number()).optional(),
      backoff_ms: z.number().optional(),
      max_backoff_ms: z.number().optional(),
    }), z.string()]).optional(),
    output_path: z.string().optional().describe("download: destination path"),
    shell: z.enum(["bash", "cmd", "powershell"]).optional().describe("as_curl: target shell syntax (default bash)"),
    // session
    session_id: z.string().optional().describe("session_create (optional name) / session_close"),
    // oauth2
    token_url: z.string().optional(),
    device_authorization_url: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
    scope: z.string().optional(),
    audience: z.string().optional(),
    refresh_token: z.string().optional(),
    device_code: z.string().optional(),
    auth_method: z.enum(["basic", "form"]).optional(),
    use_cache: z.boolean().optional(),
    max_wait_seconds: z.number().optional(),
    initial_interval: z.number().optional(),
    extra_params: z.union([z.record(z.string()), z.string()]).optional(),
  },
  async (p) => {
    try {
      const httpActions = ["request", "get", "post", "put", "delete", "patch", "head", "download"];
      if (httpActions.includes(p.action)) {
        if (!p.url) return errContent(`${p.action} requires 'url'`);
        const method = p.action === "request" ? (p.method ?? "GET")
          : p.action === "download" ? "GET"
          : p.action.toUpperCase();
        const spec: RequestSpec = { ...p, method, url: p.url };
        const res = await doRequest(spec);
        if (p.action === "download") {
          if (!p.output_path) return errContent("download requires 'output_path'");
          const buf = res.body_encoding === "base64" ? Buffer.from(res.body, "base64") : Buffer.from(res.body, "utf8");
          writeFileSync(p.output_path, buf);
          return textContent({
            path: p.output_path, bytes: buf.length, status: res.status,
            content_type: res.content_type, url: res.url, duration_ms: res.duration_ms,
            attempts: res.attempts,
          });
        }
        const resp = textContent(res);
        if (res.status >= 400) (resp as any).isError = true;
        return resp;
      }

      if (p.action === "as_curl") {
        if (!p.url) return errContent("as_curl requires 'url'");
        const cmd = toCurl({ ...p, url: p.url } as RequestSpec, p.shell ?? "bash");
        return textContent({ command: cmd, shell: p.shell ?? "bash" });
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
