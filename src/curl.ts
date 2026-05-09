import type { RequestSpec } from "./http.js";
import { buildUrl, resolveHeadersAndBody } from "./http.js";

function shellQuote(s: string, shell: "bash" | "cmd" | "powershell"): string {
  if (shell === "cmd") {
    // wrap in double quotes, escape " and %
    return `"${s.replace(/"/g, '\\"').replace(/%/g, "%%")}"`;
  }
  if (shell === "powershell") {
    // wrap in single quotes, escape '' (double single quotes)
    return `'${s.replace(/'/g, "''")}'`;
  }
  // bash: single-quoted with '\'' escape
  return `'${s.replace(/'/g, "'\\''")}'`;
}

export function toCurl(p: RequestSpec, shell: "bash" | "cmd" | "powershell" = "bash"): string {
  const u = buildUrl(p.url, p.query);
  const { headers, body } = resolveHeadersAndBody(p);
  const method = (p.method ?? (body !== undefined ? "POST" : "GET")).toUpperCase();
  const lines: string[] = [];
  // S8: explicit warning when credentials may end up inline.
  const hasCreds = !!headers["authorization"] || !!headers["cookie"] || !!headers["proxy-authorization"];
  if (hasCreds) {
    lines.push("# WARNING: this command contains plaintext Authorization/Cookie credentials");
  }
  if (shell === "cmd") {
    lines.push("# WARNING: cmd.exe quoting is best-effort; prefer bash or powershell for complex bodies");
  }
  const parts: string[] = ["curl"];
  if (method !== "GET") parts.push("-X", method);
  for (const [k, v] of Object.entries(headers)) {
    if (k === "content-length") continue;
    parts.push("-H", shellQuote(`${k}: ${v}`, shell));
  }
  if (p.follow_redirects !== false) parts.push("-L");
  if (p.reject_unauthorized === false) parts.push("-k");
  if (body !== undefined) {
    if (typeof body === "string") {
      parts.push("--data-raw", shellQuote(body, shell));
    } else {
      // binary body: use base64 inline
      parts.push(`--data-binary`, shellQuote(`@-`, shell));
      parts.push(`# (pipe: ${body.length} bytes of binary data — use file or echo base64)`);
    }
  }
  parts.push(shellQuote(u.toString(), shell));
  return parts.join(" ");
}
