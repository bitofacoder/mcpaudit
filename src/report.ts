import chalk from 'chalk';
import { Finding, Severity } from './types.js';
import { ScanResult as ScanResultType } from './scan.js';

const ORDER: Severity[] = ['high', 'medium', 'low', 'info'];

const BADGE: Record<Severity, string> = {
  high: chalk.bgRed.white.bold(' HIGH '),
  medium: chalk.bgYellow.black.bold(' MED  '),
  low: chalk.bgBlue.white.bold(' LOW  '),
  info: chalk.bgGray.white.bold(' INFO '),
};

function severityRank(f: Finding): number {
  return ORDER.indexOf(f.severity);
}

export function printReport(result: ScanResultType): void {
  const { scannedConfigs, servers, findings } = result;

  console.log();
  console.log(chalk.bold('  mcpaudit') + chalk.gray('  security scan of your MCP servers'));
  console.log();

  if (scannedConfigs.length === 0) {
    console.log(chalk.yellow('  No MCP config files found.'));
    console.log(chalk.gray('  Looked for Claude Desktop, Claude Code, Cursor, and Windsurf configs.'));
    console.log(chalk.gray('  Pass --config <path> to point at a config explicitly.'));
    console.log();
    return;
  }

  console.log(chalk.gray(`  Scanned ${scannedConfigs.length} config file(s), ${servers.length} server(s):`));
  for (const c of scannedConfigs) console.log(chalk.gray(`    • ${c}`));
  console.log();

  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✓ No issues found.'));
    console.log();
    return;
  }

  const sorted = [...findings].sort((a, b) => severityRank(a) - severityRank(b));
  for (const f of sorted) {
    console.log(`  ${BADGE[f.severity]} ${chalk.bold(f.server)} ${chalk.gray('(' + f.client + ')')}`);
    console.log(`        ${f.message}`);
    if (f.detail) console.log(chalk.gray(`        ${f.detail}`));
    console.log(chalk.gray(`        rule: ${f.rule}`));
    console.log();
  }

  printSummary(findings);
}

function printSummary(findings: Finding[]): void {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  const parts: string[] = [];
  if (counts.high) parts.push(chalk.red.bold(`${counts.high} high`));
  if (counts.medium) parts.push(chalk.yellow(`${counts.medium} medium`));
  if (counts.low) parts.push(chalk.blue(`${counts.low} low`));
  if (counts.info) parts.push(chalk.gray(`${counts.info} info`));

  console.log(chalk.bold('  Summary: ') + parts.join(chalk.gray(', ')));
  console.log();
}

export function printJson(result: ScanResultType): void {
  const out = {
    scannedConfigs: result.scannedConfigs,
    serverCount: result.servers.length,
    findings: result.findings,
  };
  console.log(JSON.stringify(out, null, 2));
}

/** Process exit code: 1 if any high-severity finding, else 0. */
export function exitCode(findings: Finding[]): number {
  return findings.some((f) => f.severity === 'high') ? 1 : 0;
}
