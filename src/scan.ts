import fs from 'fs/promises';
import { knownLocations, ConfigLocation } from './locations.js';
import { ServerConfig, Finding, ToolInfo } from './types.js';
import { configRules, toolRules } from './rules.js';

export interface ScanResult {
  scannedConfigs: string[];
  servers: ServerConfig[];
  findings: Finding[];
}

async function readJson(path: string): Promise<any | null> {
  try {
    const raw = await fs.readFile(path, 'utf-8');
    return JSON.parse(raw);
  } catch (err: any) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`Could not parse ${path}: ${err.message}`);
  }
}

function extractServers(loc: ConfigLocation, json: any): ServerConfig[] {
  const block = json?.[loc.serversKey] ?? json?.mcpServers ?? json?.mcp?.servers;
  if (!block || typeof block !== 'object') return [];
  return Object.entries(block).map(([name, raw]: [string, any]) => ({
    client: loc.client,
    configPath: loc.path,
    name,
    command: raw?.command,
    args: Array.isArray(raw?.args) ? raw.args : undefined,
    url: raw?.url,
    env: raw?.env && typeof raw.env === 'object' ? raw.env : undefined,
  }));
}

export interface ScanOptions {
  /** Extra config paths supplied by the user via --config. */
  extraPaths?: string[];
  /** Connect to each stdio server and audit its live tool list. */
  deep?: boolean;
  /** Sink for non-fatal warnings (e.g. an unreadable config). */
  onWarn?: (msg: string) => void;
}

export async function scan(opts: ScanOptions = {}): Promise<ScanResult> {
  const locations: ConfigLocation[] = [
    ...knownLocations(),
    ...(opts.extraPaths ?? []).map((p) => ({
      client: 'custom',
      path: p,
      serversKey: 'mcpServers' as const,
    })),
  ];

  const scannedConfigs: string[] = [];
  const servers: ServerConfig[] = [];

  for (const loc of locations) {
    let json: any;
    try {
      json = await readJson(loc.path);
    } catch (err: any) {
      opts.onWarn?.(err.message);
      continue;
    }
    if (json === null) continue;
    scannedConfigs.push(loc.path);
    servers.push(...extractServers(loc, json));
  }

  const findings: Finding[] = [];
  for (const server of servers) {
    findings.push(...configRules(server));
  }

  if (opts.deep) {
    const { listToolsOverStdio } = await import('./probe.js');
    for (const server of servers) {
      if (!server.command || server.url) continue;
      try {
        const tools: ToolInfo[] = await listToolsOverStdio(server);
        findings.push(...toolRules(server, tools));
      } catch (err: any) {
        opts.onWarn?.(`Deep scan of "${server.name}" failed: ${err.message}`);
      }
    }
  }

  return { scannedConfigs, servers, findings };
}
