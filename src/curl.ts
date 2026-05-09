import type { RequestSpec } from "./http.js";
import { buildUrl, resolveHeadersAndBody } from "./http.js";

function shellQuote(s: string, shell: "bash" | "cmd" | "powershell"): string {
  if (shell === "cmd") {
    // U8: cmd.exe escapes embedded quotes by doubling, not via backslash.
    // Caveat: shell quoting in cmd is fundamentally fragile — we wrap in
    // double quotes, double existing quotes and any literal `%` to defang
    // delayed-expansion. Treat as best-effort.
    return `"${s.replace(/"/g, '""').replace(/%/g, "%%")}"`;
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
  let binaryPipePrefix: string | null = null;
  if (body !== undefined) {
    if (typeof body === "string") {
      parts.push("--data-raw", shellQuote(body, shell));
    } else {
      // U4: emit a reproducible base64 pipe so the command is self-contained.
      // The base64 pipe shape differs per shell, so guard with a comment first.
      const b64 = body.toString("base64");
      lines.push(`# Binary body (${body.length} bytes); the following pipe reconstructs it:`);
      if (shell === "powershell") {
        // U13: WARNING — PowerShell does NOT pipe binary bytes byte-faithfully
        // through `[Convert]::FromBase64String(...) | curl`. Cmdlet-to-native
        // pipelines stringify each byte and tack on a trailing newline, which
        // corrupts non-text payloads. The reliable pattern is a temp file:
        lines.push("# WARNING: piping `[Convert]::FromBase64String(...) | curl` is NOT byte-faithful in PowerShell.");
        lines.push("# Use an intermediate temp file instead:");
        lines.push("#   $tmp = [IO.Path]::GetTempFileName()");
        lines.push(`#   [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String(${shellQuote(b64, shell)}))`);
        lines.push(`#   curl --data-binary "@$tmp" ${shellQuote(u.toString(), shell)}`);
        lines.push("#   Remove-Item $tmp");
        // Still emit the (broken) inline form so the command line is non-empty;
        // the warning above tells the operator to use the temp-file recipe.
        binaryPipePrefix = `[Convert]::FromBase64String(${shellQuote(b64, shell)}) | `;
      } else if (shell === "cmd") {
        // cmd has no trivial inline base64; fall back to a clear marker.
        lines.push("# WARNING: cmd.exe has no portable inline base64 — write the bytes to a file then pipe with `type file | curl --data-binary @-`");
        binaryPipePrefix = null;
      } else {
        // U12: `echo` adds a trailing newline that flips the body length; use
        // `printf '%s'` so the base64 input is byte-exact before `base64 -d`.
        binaryPipePrefix = `printf '%s' ${shellQuote(b64, shell)} | base64 -d | `;
      }
      parts.push(`--data-binary`, shellQuote(`@-`, shell));
    }
  }
  parts.push(shellQuote(u.toString(), shell));
  const curlCmd = parts.join(" ");
  lines.push(binaryPipePrefix ? `${binaryPipePrefix}${curlCmd}` : curlCmd);
  return lines.join("\n");
}
