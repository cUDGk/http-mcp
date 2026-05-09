import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { z } from "zod";
import { doRequest, type Resp } from "./http.js";

// B15: defensive zod schema for OAuth token responses
// B3: expires_in must be > 0 — providers occasionally emit 0 / negative.
const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().optional(),
  expires_in: z.number().positive().optional(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  id_token: z.string().optional(),
}).passthrough();

type TokenResponse = z.infer<typeof TokenResponseSchema>;

const DeviceAuthSchema = z.object({
  device_code: z.string().min(1),
  user_code: z.string().min(1),
  verification_uri: z.string().min(1),
  verification_uri_complete: z.string().optional(),
  expires_in: z.number().optional(),
  interval: z.number().optional(),
}).passthrough();

type CachedToken = TokenResponse & { expires_at: number };

const tokenCache = new Map<string, CachedToken>();
// S7: hard upper bound — without this an attacker (or a buggy caller) can grow
// the cache without limit by varying scope / refresh_token / fingerprint, since
// we never expire entries on insert.
const TOKEN_CACHE_MAX = 512;

// S3: Refuse to send client credentials over plaintext HTTP unless the operator
// has explicitly opted in. This catches misconfigured local mocks and copy-paste
// errors where a `http://` token endpoint would otherwise leak the secret.
function assertHttpsTokenUrl(url: string): void {
  if (process.env.HTTP_ALLOW_INSECURE_OAUTH === "1") return;
  let parsed: URL;
  try { parsed = new URL(url); }
  catch (e) { throw new Error(`invalid token_url: ${(e as Error).message}`); }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `OAuth token_url must use HTTPS (got ${parsed.protocol}). ` +
      `Set HTTP_ALLOW_INSECURE_OAUTH=1 to allow.`,
    );
  }
}

function secretFingerprint(secret: string | undefined): string | undefined {
  if (!secret) return undefined;
  // S7: hash to avoid storing the secret in the cache key while still
  // distinguishing different secrets for the same client_id.
  return createHash("sha256").update(secret).digest("hex").slice(0, 16);
}

// S4: stable JSON-encoded cache key avoids `|=` injection collisions
// (a scope containing `|` or `=` would otherwise alias to a different cache row).
function cacheKey(parts: Record<string, unknown>): string {
  const cleaned = Object.fromEntries(
    Object.entries(parts)
      .filter(([, v]) => v !== undefined && v !== null)
      .sort(([a], [b]) => a.localeCompare(b)),
  );
  return JSON.stringify(cleaned);
}

function cacheToken(key: string, tok: TokenResponse): CachedToken {
  // B3 / B13: zod already enforces positive but providers occasionally bypass.
  // Clamp the early-refresh window to avoid negative TTL.
  const safeExpires = tok.expires_in && tok.expires_in > 0 ? tok.expires_in : 3600;
  const expires_at = Date.now() + Math.max(5, safeExpires - 30) * 1000;
  const cached = { ...tok, expires_at };
  // S7: when at the cap, evict expired entries first; if still at cap, drop the
  // entry that expires soonest. Bounded LRU-ish — we don't need perfect ordering
  // (entries become useless past expiry anyway), just guaranteed termination.
  if (tokenCache.size >= TOKEN_CACHE_MAX && !tokenCache.has(key)) {
    const now = Date.now();
    for (const [k, v] of tokenCache) {
      if (v.expires_at <= now) tokenCache.delete(k);
    }
    if (tokenCache.size >= TOKEN_CACHE_MAX) {
      let victim: string | null = null;
      let victimExp = Infinity;
      for (const [k, v] of tokenCache) {
        if (v.expires_at < victimExp) { victim = k; victimExp = v.expires_at; }
      }
      if (victim) tokenCache.delete(victim);
    }
  }
  tokenCache.set(key, cached);
  return cached;
}

// B12: respect body_encoding when parsing JSON token responses.
function parseJsonBody(res: Resp): unknown {
  let text: string;
  if (res.body_encoding === "base64") {
    try {
      text = Buffer.from(res.body, "base64").toString("utf8");
    } catch (e) {
      throw new Error(`failed to decode base64 token response: ${(e as Error).message}`);
    }
  } else {
    text = res.body;
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`token response was not valid JSON: ${text.slice(0, 200)}`);
  }
}

function parseTokenResponse(res: Resp): TokenResponse {
  const raw = parseJsonBody(res);
  const parsed = TokenResponseSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`token response failed validation: ${parsed.error.message}`);
  }
  return parsed.data;
}

// U6: structured error type for non-2xx token responses
export type OAuthError = {
  ok: false;
  status: number;
  error?: string;
  error_description?: string;
  body: string;
};

function makeError(res: Resp, prefix: string): Error {
  let snippet = res.body;
  if (res.body_encoding === "base64") {
    // U11: a base64 body that fails to decode means the upstream returned bytes
    // that aren't valid UTF-8. We deliberately swallow because the downstream
    // error already carries enough signal (HTTP status + the raw body length);
    // surfacing the decode error would mask the OAuth failure with an encoding
    // complaint and confuse callers.
    try { snippet = Buffer.from(res.body, "base64").toString("utf8"); } catch {}
  }
  let parsed: Record<string, unknown> | null = null;
  // U11: same rationale — non-JSON token error responses are common (HTML
  // error pages, plain-text gateway errors). Falling back to the raw snippet
  // is the right behavior; logging the parse failure would be noise.
  try { parsed = JSON.parse(snippet) as Record<string, unknown>; } catch {}
  const err = new Error(`${prefix}: HTTP ${res.status} ${snippet.slice(0, 300)}`);
  (err as Error & { oauth_error: OAuthError }).oauth_error = {
    ok: false,
    status: res.status,
    error: typeof parsed?.error === "string" ? parsed.error : undefined,
    error_description: typeof parsed?.error_description === "string" ? parsed.error_description : undefined,
    // U6: tighten leak surface from 1000 → 200 chars
    body: snippet.slice(0, 200),
  };
  return err;
}

// S5: keys we own — caller-supplied extra_params must never override these.
const PROTECTED_FORM_KEYS = new Set([
  "grant_type", "client_id", "client_secret", "refresh_token",
  "device_code", "code", "code_verifier",
]);

function applyExtraParams(form: Record<string, string>, extra: Record<string, string> | undefined): void {
  if (!extra) return;
  for (const [k, v] of Object.entries(extra)) {
    if (PROTECTED_FORM_KEYS.has(k)) {
      throw new Error(`extra_params may not override protected OAuth field: ${k}`);
    }
    form[k] = v;
  }
}

export async function clientCredentials(p: {
  token_url: string;
  client_id: string;
  client_secret: string;
  scope?: string;
  audience?: string;
  auth_method?: "basic" | "form";
  extra_params?: Record<string, string>;
  use_cache?: boolean;
}): Promise<CachedToken> {
  assertHttpsTokenUrl(p.token_url); // S3
  const key = cacheKey({
    flow: "client_credentials",
    token_url: p.token_url,
    client_id: p.client_id,
    secret_fp: secretFingerprint(p.client_secret), // S7
    scope: p.scope,
    audience: p.audience,
  });
  if (p.use_cache !== false) {
    const hit = tokenCache.get(key);
    if (hit && hit.expires_at > Date.now()) return hit;
  }

  const authMethod = p.auth_method ?? "basic";
  const form: Record<string, string> = { grant_type: "client_credentials" };
  if (p.scope) form.scope = p.scope;
  if (p.audience) form.audience = p.audience;
  if (authMethod === "form") {
    form.client_id = p.client_id;
    form.client_secret = p.client_secret;
  }
  applyExtraParams(form, p.extra_params);

  const res = await doRequest({
    url: p.token_url,
    method: "POST",
    form,
    headers: { accept: "application/json" },
    basic_auth: authMethod === "basic" ? { user: p.client_id, password: p.client_secret } : undefined,
  });
  if (res.status < 200 || res.status >= 300) {
    throw makeError(res, "OAuth2 client_credentials failed");
  }
  const tok = parseTokenResponse(res);
  return cacheToken(key, tok);
}

export async function refreshToken(p: {
  token_url: string;
  client_id: string;
  client_secret?: string;
  refresh_token: string;
  scope?: string;
  auth_method?: "basic" | "form";
}): Promise<CachedToken> {
  assertHttpsTokenUrl(p.token_url); // S3
  const authMethod = p.auth_method ?? (p.client_secret ? "basic" : "form");
  const form: Record<string, string> = {
    grant_type: "refresh_token",
    refresh_token: p.refresh_token,
  };
  if (p.scope) form.scope = p.scope;
  if (authMethod === "form") {
    form.client_id = p.client_id;
    if (p.client_secret) form.client_secret = p.client_secret;
  }
  const res = await doRequest({
    url: p.token_url,
    method: "POST",
    form,
    headers: { accept: "application/json" },
    basic_auth: authMethod === "basic" && p.client_secret ? { user: p.client_id, password: p.client_secret } : undefined,
  });
  if (res.status < 200 || res.status >= 300) {
    throw makeError(res, "OAuth2 refresh failed");
  }
  const tok = parseTokenResponse(res);
  // B4: previous key omitted both `scope` and the refresh_token fingerprint, so
  // a second refresh request with a different refresh_token (e.g. after a
  // rotation) or different scope subset would alias the old cache entry and
  // hand back a stale access token.
  const key = cacheKey({
    flow: "refresh",
    token_url: p.token_url,
    client_id: p.client_id,
    secret_fp: secretFingerprint(p.client_secret),
    scope: p.scope,
    rt_fp: secretFingerprint(p.refresh_token),
  });
  return cacheToken(key, tok);
}

export async function deviceStart(p: {
  device_authorization_url: string;
  client_id: string;
  scope?: string;
  audience?: string;
  extra_params?: Record<string, string>;
}): Promise<{
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}> {
  assertHttpsTokenUrl(p.device_authorization_url); // S3
  const form: Record<string, string> = { client_id: p.client_id };
  if (p.scope) form.scope = p.scope;
  if (p.audience) form.audience = p.audience;
  applyExtraParams(form, p.extra_params);
  const res = await doRequest({
    url: p.device_authorization_url,
    method: "POST",
    form,
    headers: { accept: "application/json" },
  });
  if (res.status < 200 || res.status >= 300) {
    throw makeError(res, "device_authorization failed");
  }
  const raw = parseJsonBody(res);
  const parsed = DeviceAuthSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`device_authorization response failed validation: ${parsed.error.message}`);
  }
  const j = parsed.data;
  return {
    device_code: j.device_code,
    user_code: j.user_code,
    verification_uri: j.verification_uri,
    verification_uri_complete: j.verification_uri_complete,
    expires_in: j.expires_in ?? 900,
    interval: j.interval ?? 5,
  };
}

export async function devicePoll(p: {
  token_url: string;
  client_id: string;
  client_secret?: string;
  device_code: string;
  max_wait_seconds?: number;
  initial_interval?: number;
}): Promise<
  | { status: "authorized"; token: CachedToken }
  | { status: "pending"; next_action: string }
  | { status: "expired" }
  | { status: "denied"; error: string; error_description?: string; http_status?: number }
  | { status: "error"; error: string; error_description?: string; http_status: number }
> {
  assertHttpsTokenUrl(p.token_url); // S3
  const deadline = Date.now() + (p.max_wait_seconds ?? 120) * 1000;
  // interval is tracked in seconds so slow_down increments stay in the spec's units.
  let intervalSec = p.initial_interval ?? 5;
  while (Date.now() < deadline) {
    const form: Record<string, string> = {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: p.device_code,
      client_id: p.client_id,
    };
    if (p.client_secret) form.client_secret = p.client_secret;
    const res = await doRequest({
      url: p.token_url,
      method: "POST",
      form,
      headers: { accept: "application/json" },
    });
    let body: unknown = {};
    try { body = parseJsonBody(res); } catch { body = {}; }
    const bodyObj = body !== null && typeof body === "object" ? body as Record<string, unknown> : {};
    if (res.status === 200 && typeof bodyObj.access_token === "string") {
      const parsed = TokenResponseSchema.safeParse(body);
      if (!parsed.success) {
        return { status: "error", error: "invalid_token_response", error_description: parsed.error.message, http_status: res.status };
      }
      const key = cacheKey({
        flow: "device",
        token_url: p.token_url,
        client_id: p.client_id,
        secret_fp: secretFingerprint(p.client_secret),
      });
      return { status: "authorized", token: cacheToken(key, parsed.data) };
    }
    const err = String(bodyObj.error ?? "");
    const desc = bodyObj.error_description ? String(bodyObj.error_description) : undefined;
    // B14: distinguish access_denied vs other errors; surface http_status
    if (err === "authorization_pending") {
      // continue
    } else if (err === "slow_down") {
      intervalSec += 5;
    } else if (err === "expired_token") {
      return { status: "expired" };
    } else if (err === "access_denied") {
      return { status: "denied", error: err, error_description: desc, http_status: res.status };
    } else if (err) {
      return { status: "error", error: err, error_description: desc, http_status: res.status };
    } else if (res.status >= 400) {
      return { status: "error", error: `http_${res.status}`, error_description: desc, http_status: res.status };
    } else if (res.status === 200) {
      // B5: provider returned 200 with neither access_token nor a recognized
      // OAuth error code. Without this branch the loop would silently retry
      // forever (the if-chain falls through to the interval sleep), eating the
      // entire max_wait_seconds budget against a server that has nothing more
      // to say. Bail out so the caller sees the malformed response.
      return {
        status: "error",
        error: "unexpected_200",
        error_description: "200 OK missing access_token and error code",
        http_status: 200,
      };
    }
    // B4: clamp sleep to the remaining deadline so we don't oversleep past it.
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await new Promise((r) => setTimeout(r, Math.min(intervalSec * 1000, remaining)));
  }
  return { status: "pending", next_action: "call oauth2_device_poll again with the same device_code" };
}

export function listCachedTokens() {
  return Array.from(tokenCache.entries()).map(([k, v]) => ({
    key: k,
    expires_in_s: Math.max(0, Math.round((v.expires_at - Date.now()) / 1000)),
    token_type: v.token_type,
    scope: v.scope,
    has_refresh: !!v.refresh_token,
  }));
}

export function clearTokenCache() {
  const n = tokenCache.size;
  tokenCache.clear();
  return { cleared: n };
}
