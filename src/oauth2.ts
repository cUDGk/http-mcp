import { doRequest } from "./http.js";

type TokenResponse = {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  [k: string]: unknown;
};

type CachedToken = TokenResponse & { expires_at: number };

const tokenCache = new Map<string, CachedToken>();

function cacheKey(parts: Record<string, unknown>): string {
  const entries = Object.entries(parts).filter(([, v]) => v !== undefined && v !== null);
  entries.sort();
  return entries.map(([k, v]) => `${k}=${String(v)}`).join("|");
}

function cacheToken(key: string, tok: TokenResponse): CachedToken {
  const expires_at = tok.expires_in
    ? Date.now() + (tok.expires_in - 30) * 1000 // refresh 30s before expiry
    : Date.now() + 3600 * 1000;
  const cached = { ...tok, expires_at };
  tokenCache.set(key, cached);
  return cached;
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
  const key = cacheKey({
    flow: "client_credentials",
    token_url: p.token_url,
    client_id: p.client_id,
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
  if (p.extra_params) Object.assign(form, p.extra_params);

  const res = await doRequest({
    url: p.token_url,
    method: "POST",
    form,
    headers: { accept: "application/json" },
    basic_auth: authMethod === "basic" ? { user: p.client_id, password: p.client_secret } : undefined,
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`OAuth2 client_credentials failed: HTTP ${res.status} ${res.body.slice(0, 300)}`);
  }
  let tok: TokenResponse;
  try { tok = JSON.parse(res.body); } catch { throw new Error(`OAuth2 token response was not JSON: ${res.body.slice(0, 200)}`); }
  if (!tok.access_token) throw new Error(`OAuth2 response missing access_token: ${res.body.slice(0, 200)}`);
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
    throw new Error(`OAuth2 refresh failed: HTTP ${res.status} ${res.body.slice(0, 300)}`);
  }
  const tok = JSON.parse(res.body) as TokenResponse;
  const key = cacheKey({ flow: "refresh", token_url: p.token_url, client_id: p.client_id });
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
  const form: Record<string, string> = { client_id: p.client_id };
  if (p.scope) form.scope = p.scope;
  if (p.audience) form.audience = p.audience;
  if (p.extra_params) Object.assign(form, p.extra_params);
  const res = await doRequest({
    url: p.device_authorization_url,
    method: "POST",
    form,
    headers: { accept: "application/json" },
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`device_authorization failed: HTTP ${res.status} ${res.body.slice(0, 300)}`);
  }
  const j = JSON.parse(res.body);
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
  | { status: "denied"; error: string; error_description?: string }
> {
  const deadline = Date.now() + (p.max_wait_seconds ?? 120) * 1000;
  let interval = (p.initial_interval ?? 5) * 1000;
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
    const body = (() => { try { return JSON.parse(res.body); } catch { return {}; } })();
    if (res.status === 200 && body.access_token) {
      const key = cacheKey({ flow: "device", token_url: p.token_url, client_id: p.client_id });
      return { status: "authorized", token: cacheToken(key, body) };
    }
    const err = String(body.error ?? "");
    if (err === "authorization_pending") {
      // continue
    } else if (err === "slow_down") {
      interval += 5000;
    } else if (err === "expired_token") {
      return { status: "expired" };
    } else if (err === "access_denied") {
      return { status: "denied", error: err, error_description: body.error_description };
    } else if (err) {
      return { status: "denied", error: err, error_description: body.error_description };
    }
    await new Promise((r) => setTimeout(r, interval));
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
