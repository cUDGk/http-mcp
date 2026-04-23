#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Buffer } from "node:buffer";
import { z } from "zod";
import { request as undiciRequest, Agent, interceptors } from "undici";

const DEFAULT_TIMEOUT = parseInt(process.env.HTTP_TIMEOUT ?? "30000", 10);
const MAX_BODY_BYTES = parseInt(process.env.HTTP_MAX_BODY ?? "2097152", 10); // 2 MiB
const USER_AGENT = process.env.HTTP_USER_AGENT ?? "http-mcp/0.1";
const TEXTUAL = /^(text\/|application\/(json|xml|x-www-form-urlencoded|javascript|graphql|ld\+json|yaml|x-yaml))|(\+json|\+xml)$/;

type Resp = {
  url: string;
  status: number;
  status_text: string;
  http_version?: string;
  headers: Record<string, string>;
  content_type: string | null;
  content_length: number | null;
  body_encoding: "text" | "base64";
  body: string;
  body_truncated: boolean;
  redirects: string[];
  duration_ms: number;
};

function headersToObject(h: Record<string, string | string[] | undefined>): Record<string, string> {
  const o: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    o[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
  }
  return o;
}

function basicAuth(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

function isTextual(contentType: string | null): boolean {
  if (!contentType) return false;
  const lower = contentType.toLowerCase();
  return TEXTUAL.test(lower);
}

async function doRequest(p: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  body_base64?: string;
  json?: unknown;
  form?: Record<string, string>;
  query?: Record<string, string | number | boolean | (string | number)[]>;
  basic_auth?: { user: string; password: string };
  bearer?: string;
  timeout?: number;
  follow_redirects?: boolean;
  max_redirects?: number;
  reject_unauthorized?: boolean;
  max_body_bytes?: number;
}): Promise<Resp> {
  const t0 = Date.now();

  // Build URL with query params
  const u = new URL(p.url);
  if (p.query) {
    for (const [k, v] of Object.entries(p.query)) {
      if (Array.isArray(v)) for (const vv of v) u.searchParams.append(k, String(vv));
      else u.searchParams.append(k, String(v));
    }
  }

  const headers: Record<string, string> = {
    "user-agent": USER_AGENT,
    accept: "*/*",
  };
  if (p.headers) {
    for (const [k, v] of Object.entries(p.headers)) headers[k.toLowerCase()] = v;
  }

  if (p.basic_auth) headers["authorization"] = basicAuth(p.basic_auth.user, p.basic_auth.password);
  if (p.bearer) headers["authorization"] = `Bearer ${p.bearer}`;

  // Body resolution
  let body: string | Buffer | undefined;
  if (p.json !== undefined) {
    body = JSON.stringify(p.json);
    if (!headers["content-type"]) headers["content-type"] = "application/json";
  } else if (p.form) {
    body = new URLSearchParams(p.form).toString();
    if (!headers["content-type"]) headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (p.body_base64 !== undefined) {
    body = Buffer.from(p.body_base64, "base64");
  } else if (p.body !== undefined) {
    body = p.body;
  }

  const dispatcher = new Agent({
    connect: {
      rejectUnauthorized: p.reject_unauthorized !== false,
    },
    headersTimeout: p.timeout ?? DEFAULT_TIMEOUT,
    bodyTimeout: p.timeout ?? DEFAULT_TIMEOUT,
  });

  const maxRedirects = p.follow_redirects === false ? 0 : (p.max_redirects ?? 5);
  const composed = maxRedirects > 0
    ? dispatcher.compose(interceptors.redirect({ maxRedirections: maxRedirects }))
    : dispatcher;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), p.timeout ?? DEFAULT_TIMEOUT);

  try {
    const res = await undiciRequest(u.toString(), {
      method: (p.method ?? "GET").toUpperCase() as any,
      headers,
      body: body as any,
      signal: ac.signal,
      dispatcher: composed,
    });
    const respHeaders = headersToObject(res.headers as any);
    const contentType = respHeaders["content-type"] ?? null;
    const contentLength = respHeaders["content-length"] ? parseInt(respHeaders["content-length"], 10) : null;
    const maxBytes = p.max_body_bytes ?? MAX_BODY_BYTES;

    const chunks: Buffer[] = [];
    let received = 0;
    let truncated = false;
    for await (const chunk of res.body) {
      const buf = typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk);
      if (received + buf.length > maxBytes) {
        chunks.push(buf.subarray(0, maxBytes - received));
        received = maxBytes;
        truncated = true;
        try { ac.abort(); } catch {}
        break;
      }
      chunks.push(buf);
      received += buf.length;
    }
    const buffer = Buffer.concat(chunks);

    const textual = isTextual(contentType);
    const body_encoding = textual ? "text" : "base64";
    const body_out = textual ? buffer.toString("utf8") : buffer.toString("base64");

    return {
      url: u.toString(),
      status: res.statusCode,
      status_text: (res as any).statusMessage ?? "",
      headers: respHeaders,
      content_type: contentType,
      content_length: contentLength ?? buffer.length,
      body_encoding,
      body: body_out,
      body_truncated: truncated,
      redirects: (res as any).redirections?.map((r: URL) => r.toString()) ?? [],
      duration_ms: Date.now() - t0,
    };
  } finally {
    clearTimeout(timer);
  }
}

function textContent(data: unknown) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text" as const, text }] };
}

function errContent(msg: string) {
  return { content: [{ type: "text" as const, text: msg }], isError: true };
}

const server = new McpServer({ name: "http", version: "0.1.0" });

server.tool(
  "http",
  `Make HTTP requests. Structured response includes status, headers (lowercased), content-type, and body.

Response body:
- Textual types (text/*, application/json, +json/+xml, form-urlencoded, yaml, graphql) → decoded UTF-8 string (body_encoding: "text")
- Binary types → base64 (body_encoding: "base64")
- Body is capped at HTTP_MAX_BODY bytes (default 2 MiB). body_truncated: true when cut.

Body selection (choose one):
- json: any JSON-serializable value → sends as application/json
- form: object → sends as application/x-www-form-urlencoded
- body: raw string body
- body_base64: raw binary body (base64)

Auth shortcuts:
- basic_auth: { user, password } → Authorization: Basic ...
- bearer: token → Authorization: Bearer ...
Custom headers override both.

Redirects are followed by default (max 5). Disable with follow_redirects: false.

Actions:
- request: full-power request (method, url, headers, body variants, query, auth, timeout, follow_redirects).
- get / post / put / delete / patch / head: shortcuts that set method.
- download: GET + write response body to path. Returns {path, bytes, status}.`,
  {
    action: z.enum(["request", "get", "post", "put", "delete", "patch", "head", "download"]).describe("Action to perform"),
    url: z.string().describe("Request URL (may include querystring)"),
    method: z.string().optional().describe("HTTP method (request action)"),
    headers: z.record(z.string()).optional().describe("Request headers (lowercased in response)"),
    query: z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))])).optional().describe("Appended to URL querystring"),
    body: z.string().optional().describe("Raw string body"),
    body_base64: z.string().optional().describe("Raw binary body as base64"),
    json: z.unknown().optional().describe("JSON body (sets content-type)"),
    form: z.record(z.string()).optional().describe("Form-urlencoded body"),
    basic_auth: z.object({ user: z.string(), password: z.string() }).optional().describe("Basic auth"),
    bearer: z.string().optional().describe("Bearer token"),
    timeout: z.number().optional().describe("Per-call timeout ms (default HTTP_TIMEOUT)"),
    follow_redirects: z.boolean().optional().describe("Follow redirects (default true)"),
    max_redirects: z.number().optional().describe("Max redirect chain length (default 5)"),
    reject_unauthorized: z.boolean().optional().describe("TLS cert verification (default true). Set false for self-signed."),
    max_body_bytes: z.number().optional().describe("Cap response body bytes (default HTTP_MAX_BODY=2MiB)"),
    output_path: z.string().optional().describe("download: write body to this path"),
  },
  async (p) => {
    try {
      const method = p.action === "request" ? (p.method ?? "GET") :
        p.action === "download" ? "GET" :
        p.action.toUpperCase();
      const res = await doRequest({ ...p, method });
      if (p.action === "download") {
        if (!p.output_path) return errContent("download requires 'output_path'");
        const { writeFileSync } = await import("node:fs");
        const buf = res.body_encoding === "base64"
          ? Buffer.from(res.body, "base64")
          : Buffer.from(res.body, "utf8");
        writeFileSync(p.output_path, buf);
        return textContent({
          path: p.output_path,
          bytes: buf.length,
          status: res.status,
          content_type: res.content_type,
          url: res.url,
          duration_ms: res.duration_ms,
        });
      }
      const response: any = { ...res };
      if (res.status >= 400) response._note = `HTTP ${res.status} — response marked isError`;
      const mcp = textContent(response);
      if (res.status >= 400) (mcp as any).isError = true;
      return mcp;
    } catch (err: any) {
      return errContent(`HTTP error: ${err?.message ?? String(err)}${err?.cause?.message ? ` (cause: ${err.cause.message})` : ""}`);
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
