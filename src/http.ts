import { Buffer } from "node:buffer";
import { request as undiciRequest, Agent, type Dispatcher } from "undici";
import { CookieJar } from "tough-cookie";
import { isIP } from "node:net";
import { promises as dns } from "node:dns";
import { createHash, randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve as pathResolve, sep as pathSep } from "node:path";
import { createRequire } from "node:module";

const _require = createRequire(import.meta.url);
// U1: pull version from package.json at runtime; one source of truth.
export const PKG_VERSION = (_require("../package.json") as { version: string }).version;
function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    process.stderr.write(`[http-mcp] WARN: ${name}=${raw} is not a positive number; using default ${fallback}\n`);
    return fallback;
  }
  return Math.floor(n);
}

export const DEFAULT_TIMEOUT = envInt("HTTP_TIMEOUT", 30000);
export const MAX_BODY_BYTES = envInt("HTTP_MAX_BODY", 2097152);
export const DOWNLOAD_MAX_BYTES = envInt("HTTP_DOWNLOAD_MAX", 1024 * 1024 * 1024); // 1 GiB
export const SESSION_TTL_MS = envInt("HTTP_SESSION_TTL", 3600 * 1000); // 1 h idle
export const SESSION_MAX = envInt("HTTP_SESSION_MAX", 256);
export const USER_AGENT = process.env.HTTP_USER_AGENT ?? `http-mcp/${PKG_VERSION}`;

// B7: Properly grouped textual content-type matcher.
// Anchored, optional whitespace tolerated; covers text/*, application/{json,xml,javascript,
// x-www-form-urlencoded,graphql} and any application/*+json or application/*+xml structured suffix.
const TEXTUAL = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|graphql)|application\/[^;]*\+(json|xml))(;|$)/;

// S3: RFC 7230 token / field-value validation
const HDR_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HDR_VAL = /^[\t\x20-\x7E\x80-\xFF]*$/;
const BEARER_PRINTABLE = /^[\x21-\x7E]+$/;

export function sanitizeHeader(k: string, v: string): void {
  if (!HDR_NAME.test(k)) throw new Error(`invalid header name: ${JSON.stringify(k)}`);
  if (!HDR_VAL.test(v)) throw new Error(`invalid header value for ${k}`);
}

export const sessions = new Map<string, { id: string; jar: CookieJar; created_at: number; last_used: number }>();

function evictExpiredSessions(): void {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.last_used > SESSION_TTL_MS) sessions.delete(id);
  }
}

function hashSessionId(raw: string): string {
  // S6: never use caller-supplied id as the live key — hash so cross-leak is prevented.
  return "u_" + createHash("sha256").update(raw).digest("hex").slice(0, 24);
}

export function createSession(id?: string): { id: string } {
  evictExpiredSessions();
  // S6: server-generated only. If a caller supplies an id, hash it.
  const sid = id ? hashSessionId(id) : `s_${Date.now()}_${randomBytes(6).toString("hex")}`;
  if (sessions.has(sid)) {
    if (id) {
      // returning the same hashed id is fine — it lets callers re-attach
      const existing = sessions.get(sid)!;
      existing.last_used = Date.now();
      return { id: sid };
    }
    throw new Error(`session already exists: ${sid}`);
  }
  if (sessions.size >= SESSION_MAX) {
    // evict oldest by last_used
    let oldest: { id: string; last_used: number } | null = null;
    for (const s of sessions.values()) {
      if (!oldest || s.last_used < oldest.last_used) oldest = { id: s.id, last_used: s.last_used };
    }
    if (oldest) sessions.delete(oldest.id);
  }
  sessions.set(sid, { id: sid, jar: new CookieJar(), created_at: Date.now(), last_used: Date.now() });
  return { id: sid };
}

export function closeSession(id: string): { closed: boolean } {
  // accept either raw caller id or hashed id
  const direct = sessions.delete(id);
  if (direct) return { closed: true };
  return { closed: sessions.delete(hashSessionId(id)) };
}

function getSession(id: string) {
  return sessions.get(id) ?? sessions.get(hashSessionId(id));
}

export function listSessions() {
  evictExpiredSessions();
  return Array.from(sessions.values()).map((s) => ({
    id: s.id,
    created_at: s.created_at,
    last_used: s.last_used,
    age_ms: Date.now() - s.created_at,
    idle_ms: Date.now() - s.last_used,
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
  // S5: RFC 7617 forbids `:` in the user portion (it's the field separator);
  // accepting it would silently let attacker-controlled values inject a fake
  // password boundary into the credential.
  if (user.includes(":")) throw new Error("basic_auth user must not contain ':'");
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

// S1: normalize numeric IPv4 forms (hex 0x.., octal 0..., single decimal int)
// to dotted-quad before isIP / DNS so SSRF guard can reject loopback shorthand.
function normalizeNumericHost(raw: string): string {
  // single decimal int form
  const dec = /^(\d+)$/.exec(raw);
  if (dec) {
    const n = Number(dec[1]);
    if (Number.isInteger(n) && n >= 0 && n <= 0xffffffff) {
      return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
    }
  }
  // hex 0x form
  if (/^0x[0-9a-f]{1,8}$/i.test(raw)) {
    const v = parseInt(raw.slice(2), 16);
    if (Number.isFinite(v) && v >= 0 && v <= 0xffffffff) {
      return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join(".");
    }
  }
  // octal-only (leading 0 followed by digits 0-7)
  if (/^0[0-7]+$/.test(raw)) {
    const v = parseInt(raw, 8);
    if (Number.isFinite(v) && v >= 0 && v <= 0xffffffff) {
      return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join(".");
    }
  }
  return raw;
}

// S1: SSRF guard. Re-validates after DNS resolution.
export async function assertSafeUrl(u: URL): Promise<void> {
  if (!/^https?:$/.test(u.protocol)) throw new Error(`scheme not allowed: ${u.protocol}`);
  if (process.env.HTTP_ALLOW_PRIVATE === "1") return;
  // strip IPv6 brackets and zone-id, then normalize numeric IPv4 shorthand.
  let host = u.hostname.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  host = normalizeNumericHost(host);
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal")) {
    throw new Error(`blocked host: ${host}`);
  }
  const v = isIP(host);
  const checkIp = (ip: string): void => {
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(ip)) throw new Error(`blocked private ipv4: ${ip}`);
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) throw new Error(`blocked private ipv4: ${ip}`);
    // S2: include unspecified `::` (resolves to 0.0.0.0 on most stacks → SSRF).
    if (/^(::1$|::$|fe80:|fc|fd|::ffff:)/i.test(ip)) throw new Error(`blocked private ipv6: ${ip}`);
    // S1: IPv4-mapped IPv6 in dotted form (e.g. ::ffff:127.0.0.1) — extract IPv4 and re-check.
    const mappedDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
    if (mappedDotted) checkIp(mappedDotted[1]!);
    // S1: IPv4-mapped IPv6 in hex form (e.g. ::ffff:7f00:0001) — convert hi:lo to dotted IPv4.
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1]!, 16);
      const lo = parseInt(mappedHex[2]!, 16);
      checkIp(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`);
    }
  };
  if (v === 4 || v === 6) {
    checkIp(host);
    return;
  }
  // S2: reject ambiguous IPv6 host literals (e.g. ::a.b.c.d) that isIP doesn't
  // recognize but DNS may still resolve.
  if (host.includes(":")) {
    throw new Error(`blocked: ambiguous IPv6 host literal: ${host}`);
  }
  const addrs = await dns.lookup(host, { all: true });
  for (const a of addrs) checkIp(a.address);
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
  if (incomingHeaders) {
    for (const [k, v] of Object.entries(incomingHeaders)) {
      const lk = k.toLowerCase();
      const sv = String(v);
      // S3: validate before accepting
      sanitizeHeader(lk, sv);
      headers[lk] = sv;
    }
  }
  const basic = coerceObject<{ user: string; password: string }>(p.basic_auth);
  if (basic) headers["authorization"] = basicAuth(basic.user, basic.password);
  if (p.bearer) {
    if (!BEARER_PRINTABLE.test(p.bearer)) throw new Error("invalid bearer token (must be printable ASCII without whitespace)");
    headers["authorization"] = `Bearer ${p.bearer}`;
  }

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
    // B16: default Content-Type for binary body
    if (!headers["content-type"]) headers["content-type"] = "application/octet-stream";
  } else if (p.body !== undefined) {
    body = p.body;
  }
  return { headers, body };
}

// B1: cached global Agent — one socket pool reused across requests.
let globalAgent: Agent | null = null;
let globalAgentInsecure: Agent | null = null;

function getAgent(rejectUnauthorized: boolean): Agent {
  if (rejectUnauthorized) {
    if (!globalAgent) globalAgent = new Agent({ connect: { rejectUnauthorized: true } });
    return globalAgent;
  } else {
    if (!globalAgentInsecure) globalAgentInsecure = new Agent({ connect: { rejectUnauthorized: false } });
    return globalAgentInsecure;
  }
}

export async function closeGlobalAgents(): Promise<void> {
  const a = globalAgent; const b = globalAgentInsecure;
  globalAgent = null; globalAgentInsecure = null;
  if (a) await a.close();
  if (b) await b.close();
}

// Headers stripped on cross-origin redirect (S2).
const CREDENTIAL_HEADERS = new Set(["authorization", "cookie", "proxy-authorization"]);

function isSameOrigin(a: URL, b: URL): boolean {
  return a.protocol === b.protocol && a.hostname === b.hostname && (a.port || defaultPort(a.protocol)) === (b.port || defaultPort(b.protocol));
}
function defaultPort(proto: string): string {
  return proto === "https:" ? "443" : "80";
}

type StreamSink =
  | { kind: "memory"; chunks: Buffer[]; received: number; cap: number }
  | { kind: "file"; ws: NodeJS.WritableStream; received: number; cap: number; path: string };

async function consumeBody(
  body: AsyncIterable<Buffer | string>,
  sink: StreamSink,
  ac: AbortController,
  signal: { abortedByCap: boolean },
): Promise<{ truncated: boolean }> {
  let truncated = false;
  for await (const chunk of body) {
    // B8: unify chunk → Buffer
    const buf: Buffer = Buffer.isBuffer(chunk)
      ? chunk
      : typeof chunk === "string"
        ? Buffer.from(chunk)
        : Buffer.from((chunk as Uint8Array).buffer, (chunk as Uint8Array).byteOffset, (chunk as Uint8Array).byteLength);

    if (sink.received + buf.length > sink.cap) {
      const slice = buf.subarray(0, sink.cap - sink.received);
      if (sink.kind === "memory") {
        sink.chunks.push(slice);
        sink.received = sink.cap;
      } else {
        // B7: only mark file sink "received = cap" AFTER the await resolves —
        // otherwise an early write failure leaves a lying counter behind.
        await new Promise<void>((res, rej) => sink.ws.write(slice, (e) => (e ? rej(e) : res())));
        sink.received = sink.cap;
      }
      truncated = true;
      // B3: distinguish a cap-driven abort from a timeout-driven abort so the
      // outer catch can label aborted_reason correctly instead of mislabeling
      // every cap hit as "timeout".
      signal.abortedByCap = true;
      try { ac.abort(); } catch {}
      // B5: ensure socket releases — undici will see the abort
      try { (body as { destroy?: () => void }).destroy?.(); } catch {}
      break;
    }
    if (sink.kind === "memory") {
      sink.chunks.push(buf);
      sink.received += buf.length;
    } else {
      await new Promise<void>((res, rej) => sink.ws.write(buf, (e) => (e ? rej(e) : res())));
      sink.received += buf.length;
    }
  }
  return { truncated };
}

type RequestOptions = {
  toFile?: { path: string; cap: number };
};

async function doRequestOnce(p: RequestSpec, attempt: number, opts: RequestOptions = {}): Promise<Resp> {
  const t0 = Date.now();
  const startUrl = buildUrl(p.url, p.query);
  await assertSafeUrl(startUrl);
  const { headers, body } = resolveHeadersAndBody(p);

  // S4: TLS verification gate
  let rejectUnauthorized = p.reject_unauthorized !== false;
  if (!rejectUnauthorized && process.env.HTTP_ALLOW_INSECURE_TLS !== "1") {
    process.stderr.write("[http-mcp] WARN: reject_unauthorized=false ignored. Set HTTP_ALLOW_INSECURE_TLS=1 to enable.\n");
    rejectUnauthorized = true;
  }

  // Merge cookies from session jar (using starting URL — will re-resolve after redirects too)
  type SessionEntry = { id: string; jar: CookieJar; created_at: number; last_used: number };
  let sessionEntry: SessionEntry | undefined;
  if (p.session) {
    sessionEntry = getSession(p.session);
    if (!sessionEntry) throw new Error(`unknown session: ${p.session}`);
    sessionEntry.last_used = Date.now();
  }

  // S2: manual redirect handling
  const maxRedirects = p.follow_redirects === false ? 0 : (p.max_redirects ?? 5);
  const dispatcher = getAgent(rejectUnauthorized);
  const timeoutMs = p.timeout ?? DEFAULT_TIMEOUT;
  const wallDeadline = t0 + timeoutMs * Math.max(1, maxRedirects + 1);

  const redirects: string[] = [];
  let currentUrl = startUrl;
  let currentMethod = (p.method ?? "GET").toUpperCase();
  let currentHeaders: Record<string, string> = { ...headers };
  let currentBody: string | Buffer | undefined = body;
  // B2: snapshot the caller-supplied cookie ONCE so per-hop merges don't
  // accumulate stale jar cookies from prior hops.
  const callerCookie = (currentHeaders["cookie"] as string | undefined) ?? "";

  for (let hop = 0; hop <= maxRedirects; hop++) {
    // attach session cookies for this hop's URL (jar is host-aware)
    if (sessionEntry) {
      const jarCookie = await sessionEntry.jar.getCookieString(currentUrl.toString());
      // S4: a caller-supplied Cookie header is implicitly scoped to the
      // origin they typed. A redirect that moves us to another origin must
      // NOT carry that cookie forward (host-only cookies leak otherwise).
      const sameOriginAsStart = currentUrl.origin === startUrl.origin;
      const attachCaller = sameOriginAsStart ? callerCookie : "";
      const merged = [attachCaller, jarCookie].filter(Boolean).join("; ");
      if (merged) currentHeaders["cookie"] = merged;
      else delete currentHeaders["cookie"];
    }

    const ac = new AbortController();
    let abortedByTimeout = false;
    const remaining = Math.max(1, wallDeadline - Date.now());
    const timer = setTimeout(() => { abortedByTimeout = true; ac.abort(); }, Math.min(timeoutMs, remaining));

    let res: Dispatcher.ResponseData<null>;
    try {
      // maxRedirections was removed from RequestOptions types in undici 7 but still
      // accepted at runtime; cast to unknown to inject it without a full `as any`.
      type UndiciOpts = { dispatcher?: Dispatcher } & Omit<Dispatcher.RequestOptions<null>, "origin" | "path" | "method"> & Partial<Pick<Dispatcher.RequestOptions, "method">>;
      const reqOpts: UndiciOpts = {
        method: currentMethod as Dispatcher.HttpMethod,
        headers: currentHeaders,
        body: currentBody,
        signal: ac.signal,
        dispatcher,
      };
      res = await undiciRequest(currentUrl.toString(), {
        ...reqOpts,
        // S2: we handle redirects manually
        ...(({ maxRedirections: 0 }) as unknown as object),
      } as UndiciOpts);
    } catch (e: unknown) {
      clearTimeout(timer);
      // B4: distinguish AbortError vs other errors
      const asErr = e as { name?: string; code?: string } | null;
      if (asErr?.name === "AbortError" || asErr?.code === "UND_ERR_ABORTED") {
        if (abortedByTimeout) {
          throw Object.assign(new Error(`request aborted: timeout after ${timeoutMs}ms`), { name: "TimeoutError", cause: e });
        }
        throw e;
      }
      throw e;
    }

    const respHeaders = headersToObject(res.headers);
    const status = res.statusCode;

    // Manual redirect handling
    const isRedirect = status >= 300 && status < 400 && status !== 304 && respHeaders["location"];
    if (isRedirect && hop < maxRedirects) {
      // Drain body so the socket can be reused. `destroy` is the cheap path;
      // when an iterable-only stream lacks it we must consume to completion or
      // undici will keep the connection in CONNECTING state.
      try {
        const maybeDestroy = (res.body as { destroy?: unknown }).destroy;
        if (typeof maybeDestroy === "function") {
          (res.body as { destroy: () => void }).destroy();
        } else {
          for await (const _ of res.body as AsyncIterable<unknown>) { /* drain */ }
        }
      } catch {
        // best-effort: undici may already have closed it
      }
      clearTimeout(timer);
      const locationRaw = respHeaders["location"]!;
      const nextUrl = new URL(locationRaw, currentUrl);
      await assertSafeUrl(nextUrl);

      // Persist Set-Cookie from the redirect hop too (B9: jar receives cookies at every hop's URL)
      if (sessionEntry && res.headers["set-cookie"]) {
        const setCookies = Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [res.headers["set-cookie"]];
        for (const sc of setCookies) {
          try { await sessionEntry.jar.setCookie(String(sc), currentUrl.toString(), { ignoreError: true }); }
          catch { /* tough-cookie hardening: jar already lenient via ignoreError, defense in depth */ }
        }
      }

      redirects.push(nextUrl.toString());

      // S2: cross-origin → drop credential headers
      const sameOrigin = isSameOrigin(currentUrl, nextUrl);
      const newHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(currentHeaders)) {
        if (!sameOrigin && CREDENTIAL_HEADERS.has(k)) continue;
        newHeaders[k] = v;
      }
      currentHeaders = newHeaders;
      currentUrl = nextUrl;

      // 303 → GET; 301/302 historically downgrade non-GET/HEAD to GET as well
      if (status === 303 || ((status === 301 || status === 302) && currentMethod !== "GET" && currentMethod !== "HEAD")) {
        currentMethod = "GET";
        currentBody = undefined;
        delete currentHeaders["content-type"];
        delete currentHeaders["content-length"];
        delete currentHeaders["transfer-encoding"];
      }
      continue;
    }

    // B2: when hop === maxRedirects and the response is still a redirect, we
    // were previously falling through to the "final response" path and
    // returning the 3xx as if it were terminal. Drain & raise instead.
    if (isRedirect) {
      try {
        const maybeDestroy = (res.body as { destroy?: unknown }).destroy;
        if (typeof maybeDestroy === "function") (res.body as { destroy: () => void }).destroy();
        else for await (const _ of res.body as AsyncIterable<unknown>) { /* drain */ }
      } catch { /* best effort */ }
      clearTimeout(timer);
      throw new Error(`exceeded max redirects (${maxRedirects})`);
    }

    // Final response.
    const contentType = respHeaders["content-type"] ?? null;
    const contentLength = respHeaders["content-length"] ? parseInt(respHeaders["content-length"], 10) : null;

    // Store Set-Cookie in session jar (B9: against the FINAL response URL)
    if (sessionEntry && res.headers["set-cookie"]) {
      const setCookies = Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [res.headers["set-cookie"]];
      for (const sc of setCookies) {
        try { await sessionEntry.jar.setCookie(String(sc), currentUrl.toString(), { ignoreError: true }); }
        catch { /* tough-cookie hardening: jar already lenient via ignoreError, defense in depth */ }
      }
    }

    // Body handling
    let abortedReason: "timeout" | "max_body" | undefined;
    let body_encoding: "text" | "base64" = "text";
    let body_out = "";
    let body_truncated = false;
    let bytesWritten = 0;

    // B3: shared cap-abort signal — consumeBody flips it before calling ac.abort()
    // when the response exceeded the byte cap. The catch below uses it to label
    // the abort cause precisely (cap vs. wall-clock).
    const capSignal = { abortedByCap: false };
    try {
      if (opts.toFile) {
        const ws = createWriteStream(opts.toFile.path);
        const sink: StreamSink = { kind: "file", ws, received: 0, cap: opts.toFile.cap, path: opts.toFile.path };
        try {
          const r = await consumeBody(res.body, sink, ac, capSignal);
          body_truncated = r.truncated;
          bytesWritten = sink.received;
          await new Promise<void>((res2, rej) => ws.end((e?: Error | null) => (e ? rej(e) : res2())));
        } catch (e: unknown) {
          try { ws.destroy(); } catch {}
          const asErr = e as { name?: string; code?: string } | null;
          if (capSignal.abortedByCap && !abortedByTimeout) {
            abortedReason = "max_body";
          } else if (abortedByTimeout || asErr?.name === "AbortError" || asErr?.code === "UND_ERR_ABORTED") {
            abortedReason = "timeout";
          } else {
            throw e;
          }
        }
        body_encoding = "base64"; // download: no inline body
        body_out = "";
      } else {
        const cap = p.max_body_bytes ?? MAX_BODY_BYTES;
        const sink: StreamSink = { kind: "memory", chunks: [], received: 0, cap };
        try {
          const r = await consumeBody(res.body, sink, ac, capSignal);
          body_truncated = r.truncated;
          bytesWritten = sink.received;
        } catch (e: unknown) {
          const asErr = e as { name?: string; code?: string } | null;
          if (capSignal.abortedByCap && !abortedByTimeout) {
            abortedReason = "max_body";
          } else if (abortedByTimeout || asErr?.name === "AbortError" || asErr?.code === "UND_ERR_ABORTED") {
            abortedReason = "timeout";
            // keep partial body — caller learns about it via aborted_reason
          } else {
            throw e;
          }
        }
        const buffer = Buffer.concat(sink.kind === "memory" ? sink.chunks : []);
        const textual = isTextual(contentType);
        if (textual) {
          // B6: charset-aware decode
          const dec = decodeWithCharset(buffer, contentType);
          body_encoding = dec.encoding;
          body_out = dec.body;
        } else {
          body_encoding = "base64";
          body_out = buffer.toString("base64");
        }
      }
      if (body_truncated) abortedReason = abortedReason ?? "max_body";
    } finally {
      clearTimeout(timer);
    }

    return {
      url: currentUrl.toString(),
      status,
      status_text: res.statusText ?? "",
      headers: respHeaders,
      content_type: contentType,
      content_length: contentLength ?? bytesWritten,
      body_encoding,
      body: body_out,
      body_truncated,
      ...(abortedReason ? { aborted_reason: abortedReason } : {}),
      redirects, // B3: populated manually
      duration_ms: Date.now() - t0,
      attempts: attempt,
    };
  }

  throw new Error(`exceeded max redirects (${maxRedirects})`);
}

export async function doRequest(p: RequestSpec, opts: RequestOptions = {}): Promise<Resp> {
  type RetryOpts = { max?: number; on_status?: number[]; backoff_ms?: number; max_backoff_ms?: number };
  const retry = coerceObject<RetryOpts>(p.retry);
  if (!retry || !(retry.max && retry.max > 0)) {
    return doRequestOnce(p, 1, opts);
  }
  const onStatus = retry.on_status ?? [502, 503, 504];
  const backoff = retry.backoff_ms ?? 500;
  const maxBackoff = retry.max_backoff_ms ?? 10000;
  const maxAttempts = Math.max(1, retry.max) + 1;
  const retriedOn: number[] = [];
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await doRequestOnce(p, attempt, opts);
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
