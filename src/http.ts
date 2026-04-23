import { Buffer } from "node:buffer";
import { request as undiciRequest, Agent, interceptors } from "undici";
import { CookieJar } from "tough-cookie";

export const DEFAULT_TIMEOUT = parseInt(process.env.HTTP_TIMEOUT ?? "30000", 10);
export const MAX_BODY_BYTES = parseInt(process.env.HTTP_MAX_BODY ?? "2097152", 10);
export const USER_AGENT = process.env.HTTP_USER_AGENT ?? "http-mcp/0.2";

const TEXTUAL = /^(text\/|application\/(json|xml|x-www-form-urlencoded|javascript|graphql|ld\+json|yaml|x-yaml))|(\+json|\+xml)$/;

export const sessions = new Map<string, { id: string; jar: CookieJar; created_at: number; last_used: number }>();

export function createSession(id?: string): { id: string } {
  const sid = id ?? `s_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  if (sessions.has(sid)) throw new Error(`session already exists: ${sid}`);
  sessions.set(sid, { id: sid, jar: new CookieJar(), created_at: Date.now(), last_used: Date.now() });
  return { id: sid };
}

export function closeSession(id: string): { closed: boolean } {
  return { closed: sessions.delete(id) };
}

export function listSessions() {
  return Array.from(sessions.values()).map((s) => ({
    id: s.id,
    created_at: s.created_at,
    last_used: s.last_used,
    age_ms: Date.now() - s.created_at,
  }));
}

export type Resp = {
  url: string;
  status: number;
  status_text: string;
  headers: Record<string, string>;
  content_type: string | null;
  content_length: number | null;
  body_encoding: "text" | "base64";
  body: string;
  body_truncated: boolean;
  redirects: string[];
  duration_ms: number;
  attempts: number;
  retried_on?: number[];
};

export type RequestSpec = {
  url: string;
  method?: string;
  // All object-typed fields accept a JSON-encoded string fallback; the helper
  // coerceObject() unwraps them at runtime.
  headers?: Record<string, string> | string;
  body?: string;
  body_base64?: string;
  json?: unknown;
  form?: Record<string, string> | string;
  query?: Record<string, string | number | boolean | (string | number)[]> | string;
  basic_auth?: { user: string; password: string } | string;
  bearer?: string;
  timeout?: number;
  follow_redirects?: boolean;
  max_redirects?: number;
  reject_unauthorized?: boolean;
  max_body_bytes?: number;
  session?: string;
  retry?: {
    max?: number;
    on_status?: number[];
    backoff_ms?: number;
    max_backoff_ms?: number;
  } | string;
};

function headersToObject(h: Record<string, string | string[] | undefined>): Record<string, string> {
  const o: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    o[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
  }
  return o;
}

export function basicAuth(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

/**
 * Some MCP clients (notably Claude Code LLM tool-use path) marshal object /
 * array arguments to JSON strings before they reach the server, even when the
 * tool schema declares them as objects. This helper accepts either the
 * original value or a JSON-encoded string that parses back to an object /
 * array, so the rest of the code can work uniformly.
 */
export function coerceObject<T>(val: unknown): T | undefined {
  if (val === undefined || val === null) return undefined;
  if (typeof val === "string") {
    try {
      const parsed = JSON.parse(val);
      if (parsed !== null && typeof parsed === "object") return parsed as T;
    } catch {}
    return undefined;
  }
  if (typeof val === "object") return val as T;
  return undefined;
}

function isTextual(contentType: string | null): boolean {
  if (!contentType) return false;
  return TEXTUAL.test(contentType.toLowerCase());
}

export function buildUrl(url: string, query?: RequestSpec["query"]): URL {
  const u = new URL(url);
  const q = coerceObject<Record<string, unknown>>(query as any);
  if (q) {
    for (const [k, v] of Object.entries(q)) {
      if (Array.isArray(v)) for (const vv of v) u.searchParams.append(k, String(vv));
      else if (v !== undefined && v !== null) u.searchParams.append(k, String(v));
    }
  }
  return u;
}

export function resolveHeadersAndBody(p: RequestSpec): {
  headers: Record<string, string>;
  body: string | Buffer | undefined;
} {
  const headers: Record<string, string> = {
    "user-agent": USER_AGENT,
    accept: "*/*",
  };
  const incomingHeaders = coerceObject<Record<string, string>>(p.headers);
  if (incomingHeaders) for (const [k, v] of Object.entries(incomingHeaders)) headers[k.toLowerCase()] = String(v);
  const basic = coerceObject<{ user: string; password: string }>(p.basic_auth);
  if (basic) headers["authorization"] = basicAuth(basic.user, basic.password);
  if (p.bearer) headers["authorization"] = `Bearer ${p.bearer}`;

  let body: string | Buffer | undefined;
  if (p.json !== undefined) {
    // Defensive: MCP clients sometimes JSON-encode object args before send.
    // If p.json arrived as a stringified JSON object/array, unwrap it so
    // the stringify below doesn't double-encode the body.
    let val: unknown = p.json;
    if (typeof val === "string") {
      try {
        const parsed = JSON.parse(val);
        if (parsed !== null && typeof parsed === "object") val = parsed;
      } catch {}
    }
    body = JSON.stringify(val);
    if (!headers["content-type"]) headers["content-type"] = "application/json";
  } else if (p.form) {
    const f = coerceObject<Record<string, string>>(p.form);
    body = f ? new URLSearchParams(f).toString() : "";
    if (!headers["content-type"]) headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (p.body_base64 !== undefined) {
    body = Buffer.from(p.body_base64, "base64");
  } else if (p.body !== undefined) {
    body = p.body;
  }
  return { headers, body };
}

async function doRequestOnce(p: RequestSpec, attempt: number): Promise<Resp> {
  const t0 = Date.now();
  const u = buildUrl(p.url, p.query);
  const { headers, body } = resolveHeadersAndBody(p);

  // Merge cookies from session jar
  type SessionEntry = { id: string; jar: CookieJar; created_at: number; last_used: number };
  let sessionEntry: SessionEntry | undefined;
  if (p.session) {
    sessionEntry = sessions.get(p.session);
    if (!sessionEntry) throw new Error(`unknown session: ${p.session}`);
    sessionEntry.last_used = Date.now();
    const cookieHeader = await sessionEntry.jar.getCookieString(u.toString());
    if (cookieHeader) {
      headers["cookie"] = headers["cookie"] ? `${headers["cookie"]}; ${cookieHeader}` : cookieHeader;
    }
  }

  const dispatcher = new Agent({
    connect: { rejectUnauthorized: p.reject_unauthorized !== false },
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

    // Store Set-Cookie in session jar
    if (sessionEntry && res.headers["set-cookie"]) {
      const setCookies = Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [res.headers["set-cookie"]];
      for (const sc of setCookies) {
        try { await sessionEntry.jar.setCookie(String(sc), u.toString(), { ignoreError: true }); } catch {}
      }
    }

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
      attempts: attempt,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function doRequest(p: RequestSpec): Promise<Resp> {
  type RetryOpts = { max?: number; on_status?: number[]; backoff_ms?: number; max_backoff_ms?: number };
  const retry = coerceObject<RetryOpts>(p.retry as any);
  if (!retry || !(retry.max && retry.max > 0)) {
    return doRequestOnce(p, 1);
  }
  const onStatus = retry.on_status ?? [502, 503, 504];
  const backoff = retry.backoff_ms ?? 500;
  const maxBackoff = retry.max_backoff_ms ?? 10000;
  const maxAttempts = Math.max(1, retry.max) + 1;
  const retriedOn: number[] = [];
  let lastError: any;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await doRequestOnce(p, attempt);
      if (attempt >= maxAttempts || !onStatus.includes(res.status)) {
        res.retried_on = retriedOn;
        return res;
      }
      retriedOn.push(res.status);
    } catch (e) {
      lastError = e;
      if (attempt >= maxAttempts) throw e;
    }
    const delay = Math.min(maxBackoff, backoff * Math.pow(2, attempt - 1));
    await new Promise((r) => setTimeout(r, delay));
  }
  throw lastError ?? new Error("retry exhausted");
}
