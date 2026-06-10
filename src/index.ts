#!/usr/bin/env node
import chalk from 'chalk';
import { scan } from './scan.js';
import { printReport, printJson, exitCode } from './report.js';

interface Cli {
  json: boolean;
  deep: boolean;
  failOnHigh: boolean;
  configs: string[];
  help: boolean;
}

function parseArgs(argv: string[]): Cli {
  const cli: Cli = { json: false, deep: false, failOnHigh: false, configs: [], help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') cli.json = true;
    else if (a === '--deep') cli.deep = true;
    else if (a === '--fail-on-high') cli.failOnHigh = true;
    else if (a === '-h' || a === '--help') cli.help = true;
    else if (a === '--config') cli.configs.push(argv[++i]);
  }
  return cli;
}

const HELP = `
${chalk.bold('mcpaudit')} — security scanner for your installed MCP servers

${chalk.bold('Usage')}
  npx mcpaudit [options]

${chalk.bold('Options')}
  --deep            Launch each stdio server and audit its live tool list
  --json            Output machine-readable JSON
  --config <path>   Audit an extra config file (repeatable)
  --fail-on-high    Exit non-zero if any high-severity issue is found
  -h, --help        Show this help

${chalk.bold('What it checks')}
  • plaintext secrets stored in config files
  • unpinned / @latest npx & uvx packages (silent supply-chain upgrades)
  • insecure (http://) and remote transports
  • shell-wrapped launch commands
  • (--deep) tools that can run shell commands, write/delete files, or eval code
`;

async function main() {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.help) {
    console.log(HELP);
    return;
  }

  const warnings: string[] = [];
  const result = await scan({
    extraPaths: cli.configs,
    deep: cli.deep,
    onWarn: (m) => warnings.push(m),
  });

  if (cli.json) {
    printJson(result);
  } else {
    printReport(result);
    for (const w of warnings) console.error(chalk.yellow(`  ! ${w}`));
  }

  if (cli.failOnHigh) process.exitCode = exitCode(result.findings);
}

main().catch((err) => {
  console.error(chalk.red(`mcpaudit failed: ${err.message}`));
  process.exit(2);
});
