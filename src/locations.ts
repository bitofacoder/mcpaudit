import os from 'os';
import path from 'path';

export interface ConfigLocation {
  client: string;
  path: string;
  /** JSON path to the object whose keys are server names. */
  serversKey: 'mcpServers' | 'mcp.servers';
}

const home = os.homedir();
const platform = os.platform();

function claudeDesktopPath(): string {
  if (platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    return path.join(appData, 'Claude', 'claude_desktop_config.json');
  }
  return path.join(home, '.config', 'Claude', 'claude_desktop_config.json');
}

function cursorPath(): string {
  return path.join(home, '.cursor', 'mcp.json');
}

function windsurfPath(): string {
  return path.join(home, '.codeium', 'windsurf', 'mcp_config.json');
}

function claudeCodeUserPath(): string {
  return path.join(home, '.claude.json');
}

/**
 * Known config file locations across the common MCP clients. The scanner
 * checks each and silently skips any that don't exist.
 */
export function knownLocations(): ConfigLocation[] {
  return [
    { client: 'Claude Desktop', path: claudeDesktopPath(), serversKey: 'mcpServers' },
    { client: 'Claude Code', path: claudeCodeUserPath(), serversKey: 'mcpServers' },
    { client: 'Cursor', path: cursorPath(), serversKey: 'mcpServers' },
    { client: 'Windsurf', path: windsurfPath(), serversKey: 'mcpServers' },
  ];
}
