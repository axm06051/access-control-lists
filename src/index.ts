import * as readline from 'node:readline';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Ansi } from '@/domains/acl';
import { IPv4, protocols } from '@/domains/shared';
import { banner, printHelp, runIana, runLearn, runDrill } from '@/cli';

export * from '@/slices/filtering';
export * from '@/slices/infrastructure';
export * from '@/slices/web';
export * from '@/slices/management';
export * from '@/domains/iana';

function seededRng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(1664525, s) + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

const rawSeedArg = process.argv.find((a) => a.startsWith('--seed='));
const SEED: number = rawSeedArg ? parseInt(rawSeedArg.slice(7), 10) : Math.floor(Math.random() * 0xffffffff);
const rng = seededRng(SEED);

function pickWeighted<T>(items: ReadonlyArray<{ value: T; weight: number }>): T {
  const total = items.reduce((s, i) => s + i.weight, 0);
  let r = rng() * total;
  for (const item of items) {
    r -= item.weight;
    if (r <= 0) return item.value;
  }
  return items[items.length - 1]!.value;
}

function randInt(min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

function prefixToWildcard(prefix: number): string {
  const bits = (0xffffffff << (32 - prefix)) >>> 0;
  const subnet = [(bits >>> 24) & 0xff, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff].join('.');
  const ip = new IPv4(subnet);
  return ip.octets.map((o) => String(255 - parseInt(o, 10))).join('.');
}

function buildSubnet(thirdOctet: number) {
  const prefix = pickWeighted([
    { value: 24, weight: 40 },
    { value: 25, weight: 12 },
    { value: 26, weight: 12 },
    { value: 27, weight: 10 },
    { value: 28, weight: 8 },
    { value: 30, weight: 8 },
    { value: 20, weight: 5 },
    { value: 16, weight: 5 },
  ]);
  const network = `192.168.${thirdOctet}.0`;
  const hosts: string[] = [];
  return { network, prefix, wildcard: prefixToWildcard(prefix), gateway: network, hosts };
}

function buildPortTable() {
  const rows: any[] = [];
  for (const [name, port] of protocols.tcp.portMap()) {
    rows.push({ name: name.toUpperCase(), transport: 'TCP', port });
  }
  for (const [name, port] of protocols.udp.portMap()) {
    const upper = name.toUpperCase();
    const existing = rows.find((r) => r.name === upper && r.port === port);
    if (existing) {
      existing.transport = 'TCP/UDP';
    } else {
      rows.push({ name: upper, transport: 'UDP', port });
    }
  }
  return rows.sort((a, b) => a.port - b.port);
}

function buildIanaTiers() {
  return [
    { label: protocols.getPortType(80), alias: 'well-known / system ports', start: 0, stop: 1023 },
    { label: protocols.getPortType(8080), alias: 'registered / user ports', start: 1024, stop: 49151 },
    { label: protocols.getPortType(50000), alias: 'dynamic / private ports', start: 49152, stop: 65535 },
  ];
}

const topology = {
  engineering: buildSubnet(randInt(1, 240)),
  accounting: buildSubnet(randInt(1, 240) + 1),
  serverLanA: buildSubnet(randInt(1, 240) + 2),
  serverLanB: buildSubnet(randInt(1, 240) + 3),
  externalHost: '8.8.8.8',
};

const PORT_TABLE = buildPortTable();
const IANA_TIERS = buildIanaTiers();
const ANSWER_KEY: any[] = [];

async function main(): Promise<void> {
  banner('ACL Learning Console');
  console.log(Ansi.cyan('  TCP/UDP - Standard ACLs - Extended ACLs'));
  console.log(Ansi.cyan(`  Session seed: ${SEED}  (replay: --seed=${SEED})`));
  console.log(Ansi.cyan('  Type "help" to begin.\n'));

  const completer = (line: string) => {
    const spaceIdx = line.indexOf(' ');
    if (spaceIdx === -1) {
      const cmds = ['learn', 'drill', 'practice', 'exam', 'answers', 'topology', 'iana', 'help', 'exit'];
      const matches = cmds.filter((c) => c.startsWith(line.toLowerCase()));
      return [matches, line];
    }

    const cmd = line.substring(0, spaceIdx).toLowerCase();
    const arg = line.substring(spaceIdx + 1);

    if (cmd === 'learn') {
      const topics = ['tcp-udp', 'ports', 'standard', 'extended', 'placement', 'editing'];
      const matches = topics.filter((t) => t.startsWith(arg.toLowerCase()));
      return [matches, arg];
    } else if (cmd === 'drill') {
      const topics = ['wildcards', 'ports', 'ranges', 'operators', 'all'];
      const matches = topics.filter((t) => t.startsWith(arg.toLowerCase()));
      return [matches, arg];
    } else if (cmd === 'iana') {
      const parts = arg.split(/\s+/);
      const subcmd = parts[0] || '';
      
      if (subcmd === 'search' || subcmd === 'port' || subcmd === 'range') {
        // For these commands, we can't really autocomplete the arguments
        // Just return empty matches
        return [[], arg];
      } else {
        const subcmds = ['search', 'port', 'range', 'table', 'stats', 'help'];
        const matches = subcmds.filter((s) => s.startsWith(arg.toLowerCase()));
        return [matches, arg];
      }
    }

    return [[], line];
  };

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true, completer });

  let isProcessing = false;

  if (process.stdin.isTTY) {
    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);

    process.stdin.on('keypress', (str: string, key: any) => {
      if (key && key.name === 'c' && key.ctrl) {
        (rl as any).line = '';
        (rl as any).cursor = 0;
        console.log(Ansi.cyan('\nGoodbye!\n'));
        process.exit(0);
      }

      if (str === '?' && !isProcessing) {
        isProcessing = true;
        let line = (rl as any).line || '';
        const cursor = (rl as any).cursor || 0;
        
        line = line.substring(0, cursor);
        if (line.endsWith('?')) {
          line = line.slice(0, -1);
        }
        
        (rl as any).line = line;
        (rl as any).cursor = line.length;

        const words = line.split(/\s+/).filter((w: string) => w.length > 0);
        let cmd = words[0] || '';
        const arg = words.slice(1).join(' ');
        
        const validCmds = ['learn', 'drill', 'practice', 'exam', 'answers', 'topology', 'iana', 'help', 'exit'];
        const cmdMatches = validCmds.filter((c) => c.startsWith(cmd.toLowerCase()));
        if (cmdMatches.length === 1) {
          cmd = cmdMatches[0];
        }

        const allCmds: [string, string][] = [
          ['learn <topic>', 'Concept walkthrough. "learn help" for topic list'],
          ['drill <topic>', 'Flashcard memorisation. "drill help" for topics'],
          ['practice [n]', 'Guided lab 1-6. Omit n for menu'],
          ['exam', 'Timed CCNA-style mixed question session'],
          ['answers', 'Reveal full answer key (hidden by default)'],
          ['answers save', 'Write answer key to answer-key.txt'],
          ['topology', 'Show this session\'s generated network topology'],
          ['iana <cmd>', 'IANA port registry. "iana help" for commands'],
          ['help', 'Show this menu'],
          ['exit', 'Quit'],
        ];

        process.stdout.write('\n');
        if (line === '') {
          process.stdout.write(Ansi.cyan('-- Commands --\n'));
          for (const [c, desc] of allCmds) process.stdout.write(`  ${c.padEnd(20)} ${desc}\n`);
        } else {
          const partial = line.trim();
          const spaceIdx = partial.indexOf(' ');
          const firstCmd = spaceIdx === -1 ? partial : partial.substring(0, spaceIdx);
          const firstArg = spaceIdx === -1 ? '' : partial.substring(spaceIdx + 1);

          fs.appendFileSync('debug.log', `[?] line="${line}" partial="${partial}" spaceIdx=${spaceIdx} firstCmd="${firstCmd}" firstArg="${firstArg}"\n`);

          if (firstCmd === 'learn') {
            fs.appendFileSync('debug.log', `[?] Matched learn\n`);
            fs.appendFileSync('debug.log', `[?] Matched learn\n`);
            process.stdout.write(Ansi.cyan('-- Learn Topics --\n'));
            const topics: [string, string][] = [
              ['tcp-udp', 'TCP vs UDP - features, overhead, use cases'],
              ['ports', 'Port numbers, IANA tiers, session multiplexing'],
              ['standard', 'Standard ACLs - ACE order, implicit deny, wildcard'],
              ['extended', 'Extended ACLs - proto/src/dst/port matching'],
              ['placement', 'Where to apply ACLs inbound/outbound'],
              ['editing', 'Deleting ACEs, inserting, resequencing'],
            ];
            const filtered = firstArg ? topics.filter(([t]) => t.startsWith(firstArg.toLowerCase())) : topics;
            for (const [t, desc] of filtered) process.stdout.write(`  ${t.padEnd(20)} ${desc}\n`);
            if (firstArg && filtered.length === 1) {
              process.stdout.write(`  ${'<cr>'.padEnd(20)} Execute command\n`);
            }
          } else if (firstCmd === 'drill') {
            process.stdout.write(Ansi.cyan('-- Drill Topics --\n'));
            const topics: [string, string][] = [
              ['wildcards', 'Wildcard mask conversion'],
              ['ports', 'Port numbers and services'],
              ['ranges', 'IANA port ranges'],
              ['operators', 'ACL port operators'],
              ['all', 'All drill topics'],
            ];
            const filtered = firstArg ? topics.filter(([t]) => t.startsWith(firstArg.toLowerCase())) : topics;
            for (const [t, desc] of topics) process.stdout.write(`  ${t.padEnd(20)} ${desc}\n`);
            if (firstArg && filtered.length === 1) {
              process.stdout.write(`  ${'<cr>'.padEnd(20)} Execute command\n`);
            }
          } else if (firstCmd === 'iana') {
            process.stdout.write(Ansi.cyan('-- IANA Subcommands --\n'));
            const subcmd = firstArg.trim().split(/\s+/)[0] || '';
            
            if (subcmd === 'search' || subcmd === 'port' || subcmd === 'range') {
              if (subcmd === 'search') {
                process.stdout.write(`  search <term>        Search services by name or port\n`);
              } else if (subcmd === 'port') {
                process.stdout.write(`  port <number>        Look up service by port number\n`);
              } else if (subcmd === 'range') {
                process.stdout.write(`  range <min> <max>    List services in port range\n`);
              }
            } else {
              const cmds: [string, string][] = [
                ['search <term>', 'Search services by name or port'],
                ['port <number>', 'Look up service by port number'],
                ['range <min> <max>', 'List services in port range'],
                ['table [filter]', 'View full table (tcp|udp|system|user|dynamic)'],
                ['stats', 'Show registry statistics'],
                ['help', 'Show this menu'],
              ];
              for (const [c, desc] of cmds) process.stdout.write(`  ${c.padEnd(20)} ${desc}\n`);
            }
          } else {
            process.stdout.write(Ansi.cyan('-- Commands --\n'));
            const filtered = allCmds.filter((c) => c[0].toLowerCase().startsWith(firstCmd.toLowerCase()));
            if (filtered.length > 0) {
              for (const [c, desc] of filtered) process.stdout.write(`  ${c.padEnd(20)} ${desc}\n`);
              if (filtered.length === 1 && !firstArg) {
                process.stdout.write(`  ${'<cr>'.padEnd(20)} Execute command\n`);
              }
            }
          }
        }
        process.stdout.write('\n');

        isProcessing = false;
        
        let displayLine = line;
        // Don't add spaces for now - just display the line as-is
        
        process.stdout.write(Ansi.bold('acl> ') + displayLine);
        (rl as any).line = line;
        (rl as any).cursor = line.length;
        return;
      }
    });
  }

  rl.on('line', async (raw) => {
    if (isProcessing) return;
    isProcessing = true;

    const input = raw.trim();

    if (!input) {
      isProcessing = false;
      rl.prompt();
      return;
    }

    const spaceIdx = input.indexOf(' ');
    let cmd = spaceIdx === -1 ? input : input.substring(0, spaceIdx);
    const arg = spaceIdx === -1 ? '' : input.substring(spaceIdx + 1);
    const context = { topology, PORT_TABLE, IANA_TIERS, prefixToWildcard, protocols, ANSWER_KEY, SEED };

    const allCmds = ['learn', 'drill', 'practice', 'exam', 'answers', 'topology', 'iana', 'help', 'exit'];
    const matches = allCmds.filter((c) => c.startsWith(cmd.toLowerCase()));
    
    if (matches.length === 1 && matches[0]) {
      cmd = matches[0];
    }

    try {
      switch (cmd.toLowerCase()) {
        case 'learn':
          await runLearn(arg, rl, context);
          break;
        case 'drill':
          await runDrill(arg, rl, context);
          break;
        case 'practice':
          console.log(Ansi.yellow('Practice mode not yet implemented.\n'));
          break;
        case 'exam':
          console.log(Ansi.yellow('Exam mode not yet implemented.\n'));
          break;
        case 'answers':
          if (arg === 'save') {
            const outPath = path.join(process.cwd(), 'answer-key.txt');
            fs.writeFileSync(outPath, 'Answer key not yet implemented\n', 'utf8');
            console.log(Ansi.green(`\nAnswer key saved -> ${outPath}\n`));
          } else {
            console.log(Ansi.cyan('\nAnswer Key (hidden by default)\n'));
          }
          break;
        case 'topology':
          console.log(Ansi.cyan('\nSession Topology:'));
          console.log(`  Seed: ${SEED}  (replay with --seed=${SEED})\n`);
          console.log(`  Engineering:  ${topology.engineering.network}/${topology.engineering.prefix}`);
          console.log(`  Accounting:   ${topology.accounting.network}/${topology.accounting.prefix}`);
          console.log(`  Server LAN A: ${topology.serverLanA.network}/${topology.serverLanA.prefix}`);
          console.log(`  Server LAN B: ${topology.serverLanB.network}/${topology.serverLanB.prefix}`);
          console.log(`  External:     ${topology.externalHost}\n`);
          break;
        case 'iana':
          await runIana(arg, rl);
          break;
        case 'help':
          printHelp();
          break;
        case 'exit':
        case 'quit':
          console.log(Ansi.cyan('\nGoodbye!\n'));
          rl.close();
          process.exit(0);
        default:
          console.log(Ansi.yellow(`Unknown command "${input}". Type "help".`));
      }
    } catch (err) {
      console.error(Ansi.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
    }

    isProcessing = false;
    (rl as any).line = '';
    (rl as any).cursor = 0;
    rl.prompt();
  });

  rl.on('close', () => {
    process.exit(0);
  });

  rl.setPrompt(Ansi.bold('acl> '));
  rl.prompt();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
