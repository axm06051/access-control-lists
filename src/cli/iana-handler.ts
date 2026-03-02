import * as readline from 'node:readline';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Ansi } from '@/domains/acl';
import { ServiceRegistry, type Application } from '@/domains/iana';

const IANA_CSV_URL = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv';
const CACHE_PATH = path.join(process.cwd(), '.iana-cache.csv');
const CACHE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

async function fetchIanaData(): Promise<string> {
  const now = Date.now();
  
  if (fs.existsSync(CACHE_PATH)) {
    const stat = fs.statSync(CACHE_PATH);
    if (now - stat.mtime.getTime() < CACHE_MAX_AGE) {
      return fs.readFileSync(CACHE_PATH, 'utf-8');
    }
  }

  try {
    const response = await fetch(IANA_CSV_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.text();
    fs.writeFileSync(CACHE_PATH, data, 'utf-8');
    return data;
  } catch (err) {
    if (fs.existsSync(CACHE_PATH)) {
      console.log(Ansi.yellow('  (using cached IANA data)\n'));
      return fs.readFileSync(CACHE_PATH, 'utf-8');
    }
    throw err;
  }
}

function parseIanaCSV(csv: string): Application[] {
  const lines = csv.split('\n');
  if (lines.length < 2) return [];

  const headerLine = lines[0]!;
  const headers: Record<string, number> = {};
  headerLine.split(',').forEach((h, i) => {
    headers[h.trim()] = i;
  });

  const apps: Application[] = [];
  const seen = new Set<string>();

  const nameIdx = headers['Service Name'];
  const portIdx = headers['Port Number'];
  const protoIdx = headers['Transport Protocol'];
  const descIdx = headers['Description'];

  if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) return [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line) continue;

    const parts = line.split(',');
    const name = parts[nameIdx]?.trim().replace(/"/g, '') || '';
    const portStr = parts[portIdx]?.trim().replace(/"/g, '') || '';
    const protocol = parts[protoIdx]?.trim().replace(/"/g, '').toLowerCase() || '';
    const desc = descIdx !== undefined ? parts[descIdx]?.trim().replace(/"/g, '') || '' : '';

    if (!name || !portStr || !protocol) continue;

    const port = parseInt(portStr, 10);
    if (isNaN(port) || port < 0 || port > 65535) continue;

    const key = `${protocol}:${port}:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);

    apps.push({
      name,
      port,
      description: desc || 'Service',
      status: 'active',
    });
  }

  return apps;
}

async function initializeRegistry(): Promise<ServiceRegistry> {
  const registry = new ServiceRegistry();

  try {
    console.log(Ansi.cyan('  Loading IANA registry...'));
    const csv = await fetchIanaData();
    const apps = parseIanaCSV(csv);

    const tcpApps = apps.filter((a) => a.name.toLowerCase().includes('tcp') || Math.random() > 0.5);
    const udpApps = apps.filter((a) => a.name.toLowerCase().includes('udp') || Math.random() > 0.5);

    for (const app of tcpApps.slice(0, 500)) {
      registry.addService('tcp', app);
    }
    for (const app of udpApps.slice(0, 500)) {
      registry.addService('udp', app);
    }

    console.log(Ansi.green(`  Loaded ${tcpApps.length + udpApps.length} services\n`));
  } catch (err) {
    console.log(Ansi.yellow(`  Failed to load IANA data: ${err instanceof Error ? err.message : String(err)}`));
    console.log(Ansi.yellow('  Using fallback services\n'));
    
    const fallback = [
      { name: 'ftp', port: 21, description: 'File Transfer Protocol' },
      { name: 'ssh', port: 22, description: 'Secure Shell' },
      { name: 'telnet', port: 23, description: 'Telnet' },
      { name: 'smtp', port: 25, description: 'Simple Mail Transfer Protocol' },
      { name: 'domain', port: 53, description: 'Domain Name System' },
      { name: 'www', port: 80, description: 'HTTP' },
      { name: 'https', port: 443, description: 'HTTP Secure' },
    ];

    for (const svc of fallback) {
      const app: Application = {
        name: svc.name,
        port: svc.port,
        description: svc.description,
        status: 'active',
      };
      registry.addService('tcp', app);
      if ([53, 67, 68, 123, 161, 162, 514].includes(svc.port)) {
        registry.addService('udp', app);
      }
    }
  }

  return registry;
}

function formatTable(apps: Application[], maxRows: number = 50): void {
  if (apps.length === 0) {
    console.log(Ansi.yellow('  No results'));
    return;
  }

  const rows = apps.slice(0, maxRows);
  const portWidth = 6;
  const nameWidth = 20;
  const protoWidth = 8;
  const statusWidth = 12;

  console.log(`  ${'Port'.padEnd(portWidth)} ${'Name'.padEnd(nameWidth)} ${'Status'.padEnd(statusWidth)} ${'Description'.substring(0, 40)}`);
  console.log(`  ${'-'.repeat(portWidth)} ${'-'.repeat(nameWidth)} ${'-'.repeat(statusWidth)} ${'-'.repeat(40)}`);

  for (const app of rows) {
    const desc = app.description.substring(0, 40).padEnd(40);
    console.log(`  ${String(app.port).padEnd(portWidth)} ${app.name.padEnd(nameWidth)} ${(app.status || 'active').padEnd(statusWidth)} ${desc}`);
  }

  if (apps.length > maxRows) {
    console.log(`  ... and ${apps.length - maxRows} more results`);
  }
}

export async function runIana(arg: string, _rl: readline.Interface): Promise<void> {
  const registry = await initializeRegistry();
  const cmd = arg.toLowerCase().trim();

  if (!cmd || cmd === 'help' || cmd === '?') {
    console.log(Ansi.cyan('\n── IANA Registry Commands ────────────────────────────────────'));
    const cmds: [string, string][] = [
      ['search <term>', 'Search services by name or port'],
      ['port <number>', 'Look up service by port number'],
      ['range <min> <max>', 'List services in port range'],
      ['table [filter]', 'View full table (tcp|udp|system|user|dynamic)'],
      ['stats', 'Show registry statistics'],
      ['help', 'Show this menu'],
    ];
    for (const [c, desc] of cmds) console.log(`  ${c.padEnd(20)} ${desc}`);
    console.log();
    return;
  }

  const parts = cmd.split(/\s+/);
  let subCmd = parts[0] || '';

  const validSubCmds = ['search', 'port', 'range', 'table', 'stats', 'help'];
  const matches = validSubCmds.filter((c) => c.startsWith(subCmd));
  if (matches.length === 1 && matches[0]) {
    subCmd = matches[0];
  }

  if (subCmd === 'stats') {
    const stats = registry.getStats();
    console.log(Ansi.cyan('\nIANA Registry Statistics:'));
    console.log(`  Total Services: ${stats.totalServices}`);
    console.log(`  TCP: ${stats.protocolCounts.tcp}`);
    console.log(`  UDP: ${stats.protocolCounts.udp}`);
    console.log(`  SCTP: ${stats.protocolCounts.sctp}`);
    console.log(`  DCCP: ${stats.protocolCounts.dccp}`);
    console.log();
    return;
  }

  if (subCmd === 'search') {
    if (parts.length < 2) {
      console.log(Ansi.yellow('\nUsage: iana search <term>\n'));
      return;
    }
    const term = parts.slice(1).join(' ');
    const results = registry.search({ searchTerm: term });
    if (results.length === 0) {
      console.log(Ansi.yellow(`\nNo services found for "${term}"\n`));
      return;
    }
    console.log(Ansi.cyan(`\nServices matching "${term}":`));
    formatTable(results, 20);
    console.log();
    return;
  }

  if (subCmd === 'port' && parts.length > 1) {
    const portSpec = parts.slice(1).join(' ');
    if (!portSpec) {
      console.log(Ansi.yellow('\nInvalid port specification\n'));
      return;
    }

    const allResults: Application[] = [];
    const portSpecs = portSpec.split(',').map((s) => s.trim());

    for (const spec of portSpecs) {
      if (spec.includes('-')) {
        const parts = spec.split('-').map((s) => s.trim());
        const minStr = parts[0] || '';
        const maxStr = parts[1] || '';
        const min = parseInt(minStr, 10);
        const max = parseInt(maxStr, 10);
        if (isNaN(min) || isNaN(max)) {
          console.log(Ansi.yellow(`\nInvalid port range: ${spec}\n`));
          return;
        }
        const results = registry.search({ portRange: { min, max } });
        allResults.push(...results);
      } else {
        const port = parseInt(spec, 10);
        if (isNaN(port)) {
          console.log(Ansi.yellow(`\nInvalid port number: ${spec}\n`));
          return;
        }
        const results = registry.search({ portRange: { min: port, max: port } });
        allResults.push(...results);
      }
    }

    if (allResults.length === 0) {
      console.log(Ansi.yellow(`\nNo services found for: ${portSpec}\n`));
      return;
    }

    console.log(Ansi.cyan(`\nServices for: ${portSpec}`));
    formatTable(allResults, 50);
    console.log();
    return;
  }

  if (subCmd === 'range' && parts.length > 2) {
    const minStr = parts[1];
    const maxStr = parts[2];
    if (!minStr || !maxStr) {
      console.log(Ansi.yellow('\nInvalid port range\n'));
      return;
    }
    const min = parseInt(minStr, 10);
    const max = parseInt(maxStr, 10);
    if (isNaN(min) || isNaN(max)) {
      console.log(Ansi.yellow('\nInvalid port range\n'));
      return;
    }
    const results = registry.search({ portRange: { min, max } });
    console.log(Ansi.cyan(`\nServices in range ${min}–${max}:`));
    formatTable(results);
    console.log();
    return;
  }

  if (subCmd === 'table') {
    let results = registry.search({});
    
    if (parts.length > 1) {
      const filterType = parts[1];
      if (filterType === 'tcp' || filterType === 'udp' || filterType === 'sctp' || filterType === 'dccp') {
        results = registry.search({ protocols: [filterType as any] });
      } else if (filterType === 'system') {
        results = registry.search({ portType: ['system'] });
      } else if (filterType === 'user') {
        results = registry.search({ portType: ['user'] });
      } else if (filterType === 'dynamic') {
        results = registry.search({ portType: ['dynamic'] });
      }
    }

    console.log(Ansi.cyan(`\nIANA Services Table (${results.length} total):`));
    formatTable(results, 50);
    console.log();
    return;
  }

  console.log(Ansi.yellow(`Unknown IANA command. Type "iana help".\n`));
}
