export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface ServerConfig {
  client: string;
  configPath: string;
  name: string;
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
}

export interface Finding {
  severity: Severity;
  rule: string;
  server: string;
  client: string;
  message: string;
  detail?: string;
}

/** A live tool definition pulled from a server over stdio (deep scan). */
export interface ToolInfo {
  name: string;
  description?: string;
}
