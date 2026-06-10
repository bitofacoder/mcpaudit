import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ServerConfig, ToolInfo } from './types.js';

/**
 * Launch a stdio MCP server exactly as the client config would, list its
 * tools, and shut it down. Used by the deep scan. Times out so a hanging
 * server can't stall the audit.
 */
export async function listToolsOverStdio(
  server: ServerConfig,
  timeoutMs = 15000
): Promise<ToolInfo[]> {
  if (!server.command) throw new Error('no command to launch');

  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args ?? [],
    env: { ...process.env, ...(server.env ?? {}) } as Record<string, string>,
  });

  const client = new Client({ name: 'mcpaudit', version: '0.1.0' }, { capabilities: {} });

  const withTimeout = <T>(p: Promise<T>): Promise<T> =>
    Promise.race([
      p,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error(`timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);

  try {
    await withTimeout(client.connect(transport));
    const res = await withTimeout(client.listTools());
    return (res.tools ?? []).map((t) => ({ name: t.name, description: t.description }));
  } finally {
    await client.close().catch(() => {});
  }
}
