import { Finding, ServerConfig, ToolInfo } from './types.js';

// Env var names that look like real secrets rather than config flags.
const SECRET_KEY = /(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PAT)$/i;
// Values that are obviously placeholders, not live secrets.
const PLACEHOLDER = /^(your_|<|xxx|changeme|example|\$\{|null|none)/i;

// Tool name / description patterns that indicate the server can act on the host.
const DANGEROUS_TOOL = [
  { re: /exec|shell|terminal|run[_-]?command|spawn|subprocess/i, label: 'arbitrary command execution' },
  { re: /write[_-]?file|delete|remove|rm[_-]|unlink|overwrite/i, label: 'destructive filesystem writes' },
  { re: /eval|run[_-]?code|python|node[_-]?eval/i, label: 'arbitrary code evaluation' },
];

/** Static checks against a parsed server config entry. */
export function configRules(server: ServerConfig): Finding[] {
  const findings: Finding[] = [];
  const base = { server: server.name, client: server.client };

  // Plaintext secrets sitting in the config file.
  for (const [k, v] of Object.entries(server.env ?? {})) {
    if (SECRET_KEY.test(k) && v && !PLACEHOLDER.test(v)) {
      findings.push({
        ...base,
        severity: 'high',
        rule: 'plaintext-secret',
        message: `Secret "${k}" is stored in plaintext in the config file.`,
        detail: `Anyone with read access to ${server.configPath} can read this credential. Prefer an OS keychain or a per-shell env var.`,
      });
    }
  }

  // npx/uvx without a pinned version = silent supply-chain upgrades.
  const argStr = (server.args ?? []).join(' ');
  if (server.command && /\b(npx|uvx)\b/.test(server.command) || /\b(npx|uvx)\b/.test(argStr)) {
    const pkgArgs = (server.args ?? []).filter((a) => !a.startsWith('-'));
    const pinned = pkgArgs.some((a) => /@(\d|\^|~|>=)/.test(a) || /==/.test(a));
    const usesLatest = /@latest/.test(argStr);
    if (!pinned || usesLatest) {
      findings.push({
        ...base,
        severity: 'medium',
        rule: 'unpinned-package',
        message: usesLatest
          ? 'Server runs @latest — it can change code on every launch without review.'
          : 'Server package is not version-pinned — it can change code between launches.',
        detail: 'A compromised or updated upstream package executes on your machine with no review step. Pin to a known version.',
      });
    }
  }

  // Remote servers send your prompts/context off-machine.
  if (server.url) {
    const isHttp = /^http:\/\//i.test(server.url);
    findings.push({
      ...base,
      severity: isHttp ? 'high' : 'info',
      rule: isHttp ? 'insecure-transport' : 'remote-server',
      message: isHttp
        ? `Remote server uses plaintext HTTP (${server.url}).`
        : `Remote server — context is sent to ${safeHost(server.url)}.`,
      detail: isHttp
        ? 'Traffic (including tokens passed in headers) is unencrypted and interceptable. Require HTTPS.'
        : 'Remote MCP servers receive whatever the agent decides to send. Confirm you trust the operator.',
    });
  }

  // Inline shell wrappers in the launch command itself.
  if (server.command && /\b(sh|bash|zsh)\b/.test(server.command) && argStr.includes('-c')) {
    findings.push({
      ...base,
      severity: 'medium',
      rule: 'shell-wrapped-launch',
      message: 'Server is launched through a shell -c invocation.',
      detail: 'Shell-wrapped launch commands are easy to tamper with and hard to audit. Prefer a direct binary + args.',
    });
  }

  return findings;
}

/** Checks against the live tool list from a server (deep scan). */
export function toolRules(server: ServerConfig, tools: ToolInfo[]): Finding[] {
  const findings: Finding[] = [];
  const base = { server: server.name, client: server.client };

  for (const tool of tools) {
    const haystack = `${tool.name} ${tool.description ?? ''}`;
    for (const { re, label } of DANGEROUS_TOOL) {
      if (re.test(haystack)) {
        findings.push({
          ...base,
          severity: 'high',
          rule: 'dangerous-tool',
          message: `Exposes "${tool.name}" — ${label}.`,
          detail: 'This tool lets the model take real action on your host. Make sure the server gates it behind an explicit opt-in, and that you trust the model driving it.',
        });
        break;
      }
    }
  }

  return findings;
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
