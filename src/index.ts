import * as readline from 'node:readline';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AccessList, AclId } from './types/acls.js';
import { Ansi, AclKind, ReservedRanges, AclRange, Operation } from './types/constants.js';
import { IPv4, protocols, Packet } from './types/protocols.js';
import { operationName, inferKindFromNumber, WildcardMatcher, PortCondition, PortMatcher } from './types/utils.js';

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

const WEIGHTED_PREFIXES = [
  { value: 24, weight: 40 },
  { value: 25, weight: 12 },
  { value: 26, weight: 12 },
  { value: 27, weight: 10 },
  { value: 28, weight: 8 },
  { value: 30, weight: 8 },
  { value: 20, weight: 5 },
  { value: 16, weight: 5 },
] as const;

type GatewayStyle = 'first' | 'last' | 'second' | 'penultimate';
const WEIGHTED_GATEWAY_STYLES: ReadonlyArray<{ value: GatewayStyle; weight: number }> = [
  { value: 'first', weight: 55 },
  { value: 'last', weight: 25 },
  { value: 'second', weight: 10 },
  { value: 'penultimate', weight: 10 },
];

function hostCount(prefix: number): number {
  return Math.pow(2, 32 - prefix) - 2;
}

function wildcardFromPrefix(prefix: number): string {
  const bits = (0xffffffff << (32 - prefix)) >>> 0;
  const sub = [(bits >>> 24) & 0xff, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff];
  return sub.map((o) => String(255 - o)).join('.');
}

function subnetToWildcard(subnetStr: string): string {
  const ip = new IPv4(subnetStr);
  return ip.octets.map((o) => String(255 - parseInt(o, 10))).join('.');
}

function prefixToWildcard(prefix: number): string {
  const bits = (0xffffffff << (32 - prefix)) >>> 0;
  const subnet = [(bits >>> 24) & 0xff, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff].join('.');
  return subnetToWildcard(subnet);
}

function broadcastOffset(prefix: number): number {
  return Math.pow(2, 32 - prefix) - 1;
}

function gatewayOffset(style: GatewayStyle, prefix: number): number {
  const last = broadcastOffset(prefix) - 1;
  switch (style) {
    case 'first':
      return 1;
    case 'last':
      return last;
    case 'second':
      return 2;
    case 'penultimate':
      return last - 1;
  }
}

function ipFromOffset(network: string, prefix: number, offset: number): string {
  const parts = network.split('.').map(Number);
  const networkInt = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  const maskBits = (0xffffffff << (32 - prefix)) >>> 0;
  const hostInt = (networkInt & maskBits) + offset;
  return [(hostInt >>> 24) & 0xff, (hostInt >>> 16) & 0xff, (hostInt >>> 8) & 0xff, hostInt & 0xff].join('.');
}

function pickHostOffsets(count: number, prefix: number, reserved: number[]): number[] {
  const maxOffset = broadcastOffset(prefix) - 1;
  const minHost = Math.min(10, maxOffset);
  const maxHost = Math.min(200, maxOffset);
  const pool: number[] = [];
  for (let i = minHost; i <= maxHost; i++) {
    if (!reserved.includes(i)) pool.push(i);
  }
  const chosen: number[] = [];
  const available = [...pool];
  for (let i = 0; i < count && available.length; i++) {
    const idx = Math.floor(rng() * available.length);
    chosen.push(available.splice(idx, 1)[0]!);
  }
  return chosen.sort((a, b) => a - b);
}

interface Subnet {
  network: string;
  prefix: number;
  wildcard: string;
  gateway: string;
  gatewayStyle: GatewayStyle;
  hosts: string[];
}

function buildSubnet(thirdOctet: number): Subnet {
  const prefix = pickWeighted(WEIGHTED_PREFIXES);
  const gatewayStyle = pickWeighted(WEIGHTED_GATEWAY_STYLES);
  const gwOffset = gatewayOffset(gatewayStyle, prefix);
  const network = `192.168.${thirdOctet}.0`;
  const gateway = ipFromOffset(network, prefix, gwOffset);
  const offsets = pickHostOffsets(4, prefix, [gwOffset]);
  const hosts = offsets.map((o) => ipFromOffset(network, prefix, o));
  return { network, prefix, wildcard: wildcardFromPrefix(prefix), gateway, gatewayStyle, hosts };
}

const EXTERNAL_SOURCES: ReadonlyArray<{ value: string; weight: number; parts: number }> = [
  { value: '172.16', weight: 20, parts: 2 },
  { value: '172.17', weight: 8, parts: 2 },
  { value: '172.31', weight: 8, parts: 2 },
  { value: '203.0.113', weight: 25, parts: 3 },
  { value: '198.51.100', weight: 15, parts: 3 },
  { value: '8.8', weight: 14, parts: 2 },
  { value: '1.1', weight: 10, parts: 2 },
];

function buildExternalHost(): string {
  const total = EXTERNAL_SOURCES.reduce((s, i) => s + i.weight, 0);
  let r = rng() * total;
  const src =
    EXTERNAL_SOURCES.find((item) => {
      r -= item.weight;
      return r <= 0;
    }) ?? EXTERNAL_SOURCES[EXTERNAL_SOURCES.length - 1]!;
  if (src.parts === 2) return `${src.value}.${randInt(1, 254)}.${randInt(1, 254)}`;
  return `${src.value}.${randInt(1, 254)}`;
}

const EXAM_BLOCK_OPTIONS: ReadonlyArray<{ value: { network: string; prefix: number }; weight: number }> = [
  { value: { network: '10.0.0.0', prefix: 8 }, weight: 50 },
  { value: { network: '10.10.0.0', prefix: 16 }, weight: 20 },
  { value: { network: '10.1.0.0', prefix: 16 }, weight: 15 },
  { value: { network: '172.16.0.0', prefix: 12 }, weight: 15 },
];

const base192ThirdOctetStart = randInt(1, 240);

const topology = {
  engineering: buildSubnet(base192ThirdOctetStart),
  accounting: buildSubnet(base192ThirdOctetStart + 1),
  serverLanA: buildSubnet(base192ThirdOctetStart + 2),
  serverLanB: buildSubnet(base192ThirdOctetStart + 3),
  externalHost: buildExternalHost(),
} as const;

function buildExamScenario() {
  const block = pickWeighted(EXAM_BLOCK_OPTIONS);
  const testSrc = ipFromOffset(block.network, block.prefix, randInt(2, Math.min(hostCount(block.prefix) - 1, 65534)));
  const testDst = topology.serverLanA.hosts[0] ?? topology.serverLanA.gateway;
  return { network: block.network, prefix: block.prefix, wildcard: wildcardFromPrefix(block.prefix), testSrc, testDst };
}

const examScenario = buildExamScenario();

function buildDrillCases(): ReadonlyArray<{ src: string; target: string; wc: string; expected: boolean }> {
  const subnets = [topology.engineering, topology.accounting, topology.serverLanA, topology.serverLanB];
  const cases: Array<{ src: string; target: string; wc: string; expected: boolean }> = [];

  for (const subnet of subnets) {
    const matchHost = subnet.hosts[0];
    if (matchHost) {
      cases.push({ src: matchHost, target: subnet.network, wc: subnet.wildcard, expected: true });
    }
    const other = subnets.find((s) => s.network !== subnet.network);
    if (other?.hosts[0]) {
      cases.push({ src: other.hosts[0], target: subnet.network, wc: subnet.wildcard, expected: false });
    }
  }

  for (let i = cases.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = cases[i]!;
    cases[i] = cases[j]!;
    cases[j] = tmp;
  }
  return cases.slice(0, 4);
}

const DRILL_CASES = buildDrillCases();

type Transport = 'TCP' | 'UDP' | 'TCP/UDP';
interface PortRow {
  name: string;
  transport: Transport;
  port: number;
}

function buildPortTable(): PortRow[] {
  const rows: PortRow[] = [];
  for (const [name, port] of protocols.tcp.portMap()) {
    rows.push({ name: name.toUpperCase(), transport: 'TCP', port });
  }
  const ftp21 = protocols.tcp.resolvePort('21');
  if (ftp21 !== null && !rows.find((r) => r.port === ftp21 && r.transport === 'TCP')) {
    rows.push({ name: 'FTP', transport: 'TCP', port: ftp21 });
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
  const snmp162 = protocols.udp.resolvePort('162');
  if (snmp162 !== null && !rows.find((r) => r.port === snmp162 && r.transport === 'UDP')) {
    rows.push({ name: 'SNMP', transport: 'UDP', port: snmp162 });
  }
  return rows.sort((a, b) => a.port - b.port);
}

const PORT_TABLE: PortRow[] = buildPortTable();

interface IanaTier {
  label: string;
  alias: string;
  start: number;
  stop: number;
}

function buildIanaTiers(): IanaTier[] {
  const systemLabel = protocols.getPortType(80);
  const userLabel = protocols.getPortType(8080);
  const ephemeralLabel = protocols.getPortType(50000);
  return [
    { label: systemLabel, alias: 'well-known / system ports', start: 0, stop: 1023 },
    { label: userLabel, alias: 'registered / user ports', start: 1024, stop: 49151 },
    { label: ephemeralLabel, alias: 'dynamic / private ports', start: 49152, stop: 65535 },
  ];
}

const IANA_TIERS: IanaTier[] = buildIanaTiers();

function rangeStr(kind: AclKind): string {
  return ReservedRanges[kind].map((r: AclRange) => `${r.start}–${r.stop}`).join(', ');
}

function midpoint(r: AclRange): number {
  return r.start + Math.floor((r.stop - r.start) / 2);
}

function makeRl(): readline.Interface {
  return readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
}

function ask(rl: readline.Interface, prompt: string): Promise<string> {
  return new Promise((resolve) => rl.question(prompt, resolve));
}

async function pressEnter(rl: readline.Interface): Promise<void> {
  await ask(rl, Ansi.cyan('  [Enter to continue] '));
}

function silently<T>(fn: () => T): T {
  const orig = console.log;
  console.log = () => undefined;
  try {
    return fn();
  } finally {
    console.log = orig;
  }
}

const W = 66;

function banner(title: string): void {
  const pad = Math.floor((W - title.length) / 2);
  const inner = ' '.repeat(pad) + title + ' '.repeat(W - pad - title.length);
  console.log(Ansi.bold(Ansi.cyan(`╔${'═'.repeat(W)}╗`)));
  console.log(Ansi.bold(Ansi.cyan(`║${inner}║`)));
  console.log(Ansi.bold(Ansi.cyan(`╚${'═'.repeat(W)}╝`)));
}

function section(title: string): void {
  console.log('\n' + Ansi.bold(Ansi.cyan(`── ${title} ${'─'.repeat(Math.max(0, W - 4 - title.length))}`)));
}

function rule(): void {
  console.log(Ansi.cyan('─'.repeat(W)));
}

interface Answer {
  id: string;
  section: string;
  question: string;
  answer: string;
}
const ANSWER_KEY: Answer[] = [];

function ans(id: string, sec: string, question: string, answer: string): void {
  ANSWER_KEY.push({ id, section: sec, question, answer });
}

function buildAnswerKey(): void {
  const prefixes = [8, 16, 20, 24, 25, 27, 28, 30];
  prefixes.forEach((p, i) => {
    const wc = prefixToWildcard(p);
    ans(`D-WC-${i + 1}`, 'Drill/Wildcards', `Wildcard mask for /${p}`, wc);
  });

  PORT_TABLE.forEach((row, i) => {
    ans(`D-PORT-${i + 1}`, 'Drill/Ports', `Port number for ${row.name} (${row.transport})`, String(row.port));
  });

  let ri = 1;
  for (const [kind, ranges] of Object.entries(ReservedRanges) as [AclKind, AclRange[]][]) {
    for (const r of ranges) {
      ans(`D-RANGE-${ri++}`, 'Drill/ACL Ranges', `What ACL kind uses the range ${r.start}–${r.stop}?`, kind);
    }
    ans(`D-RANGE-${ri++}`, 'Drill/ACL Ranges', `All numbered ranges for ${kind} ACLs?`, rangeStr(kind));
  }

  IANA_TIERS.forEach((t, i) => {
    ans(
      `D-IANA-${i + 1}`,
      'Drill/IANA Tiers',
      `Port range for IANA "${t.label}" tier?`,
      `${t.start}–${t.stop} (${t.alias})`
    );
  });

  const opCases: [string, string][] = [
    ['eq 443', 'equal to 443'],
    ['gt 1023', 'greater than 1023 (not including 1023)'],
    ['lt 1024', 'less than 1024 (not including 1024)'],
    ['neq 23', 'not equal to 23'],
    ['range 80 100', '80 to 100 inclusive'],
  ];
  opCases.forEach(([op, meaning], i) => {
    ans(`D-OP-${i + 1}`, 'Drill/Port Operators', `What does ACE port operator "${op}" match?`, meaning);
  });

  const eng = topology.engineering;
  const acc = topology.accounting;
  const srvA = topology.serverLanA;
  const marthaIp = eng.hosts[1] ?? eng.hosts[0] ?? eng.gateway;
  const bobIp = acc.hosts[1] ?? acc.hosts[0] ?? acc.gateway;
  const httpsPort = PORT_TABLE.find((r) => r.name === 'HTTPS')!.port;
  const tftpPort = PORT_TABLE.find((r) => r.name === 'TFTP')!.port;

  ans(
    'LAB-1',
    'Practice Lab 1',
    `Deny ${eng.network}/${eng.prefix}, permit all others. Standard numbered ACL.`,
    [`access-list 10 deny ${eng.network} ${eng.wildcard}`, 'access-list 10 permit any'].join('\n')
  );
  ans(
    'LAB-2',
    'Practice Lab 2',
    `Deny two specific hosts (${marthaIp} and ${bobIp}), permit rest. Standard named ACL "BLOCK_HOSTS".`,
    ['ip access-list standard BLOCK_HOSTS', `  deny host ${marthaIp}`, `  deny host ${bobIp}`, '  permit any'].join(
      '\n'
    )
  );
  ans(
    'LAB-3',
    'Practice Lab 3',
    'Permit only HTTPS from engineering to server LAN. Extended numbered ACL.',
    [
      `access-list 101 permit tcp ${eng.network} ${eng.wildcard} ${srvA.network} ${srvA.wildcard} eq ${httpsPort}`,
      'access-list 101 deny ip any any',
    ].join('\n')
  );
  ans(
    'LAB-4',
    'Practice Lab 4',
    'Deny TFTP from accounting to any. Extended named ACL "NO_TFTP".',
    [
      'ip access-list extended NO_TFTP',
      `  deny udp ${acc.network} ${acc.wildcard} any eq ${tftpPort}`,
      '  permit ip any any',
    ].join('\n')
  );
  ans(
    'LAB-5',
    'Practice Lab 5',
    'Delete ACE seq 30 from numbered ACL 1 without destroying the whole ACL.',
    ['ip access-list standard 1', '  no 30'].join('\n')
  );
  ans('LAB-6', 'Practice Lab 6', 'Resequence ACL 101: start=10, increment=10.', 'ip access-list resequence 101 10 10');

  const permitStr = operationName(Operation.Permit);
  const denyStr = operationName(Operation.Deny);

  ans(
    'EXAM-01',
    'Exam',
    'What happens when a packet matches no ACE in an ACL?',
    `${denyStr} — implicit deny discards the packet silently. (Ch.23 §23.1.2)`
  );
  ans(
    'EXAM-02',
    'Exam',
    'Standard ACLs filter packets based on which field only?',
    'Source IP address. (Ch.23 §23.1.4)'
  );
  ans('EXAM-03', 'Exam', 'Extended ACLs should be placed as close to the ___ as possible.', 'SOURCE. (Ch.24 §24.1.1)');
  ans(
    'EXAM-04',
    'Exam',
    'Standard ACLs should be placed as close to the ___ as possible.',
    'DESTINATION. (Ch.23 §23.2.1)'
  );
  ans(
    'EXAM-05',
    'Exam',
    `ACL number 150 — ${AclKind.Standard} or ${AclKind.Extended}?`,
    `${inferKindFromNumber(150)} (range ${rangeStr(AclKind.Extended)}). (Ch.23 §23.2.1)`
  );
  ans(
    'EXAM-06',
    'Exam',
    `ACL number 50 — ${AclKind.Standard} or ${AclKind.Extended}?`,
    `${inferKindFromNumber(50)} (range ${rangeStr(AclKind.Standard)}). (Ch.23 §23.2.1)`
  );
  ans('EXAM-07', 'Exam', 'A wildcard bit of 0 means what?', 'That bit MUST match the ACE target. (Ch.23 §23.2.1)');
  ans('EXAM-08', 'Exam', 'A wildcard bit of 1 means what?', "That bit is ignored (don't care). (Ch.23 §23.2.1)");
  ans(
    'EXAM-09',
    'Exam',
    'TCP connection establishment sequence (three-way handshake)?',
    'SYN → SYN-ACK → ACK. (Ch.22 §22.2.1)'
  );
  ans(
    'EXAM-10',
    'Exam',
    'TCP connection termination sequence (four-way handshake)?',
    'FIN → ACK → FIN → ACK. (Ch.22 §22.2.1)'
  );
  ans(
    'EXAM-11',
    'Exam',
    'IANA ephemeral port range?',
    (() => {
      const t = IANA_TIERS.find((t) => t.start === 49152)!;
      return `${t.start}–${t.stop} (${t.alias}). (Ch.22 §22.1.1)`;
    })()
  );
  ans(
    'EXAM-12',
    'Exam',
    'How do you delete a single ACE from a numbered ACL without destroying it?',
    'Enter named ACL config mode (ip access-list standard|extended <id>), then: no <seq>. (Ch.24 §24.3.1)'
  );
  ans(
    'EXAM-13',
    'Exam',
    'What is a "shadowed rule"?',
    'An ACE that can never match because a preceding less-specific ACE already covers it. (Ch.23 §23.1.1)'
  );
  ans(
    'EXAM-14',
    'Exam',
    'Which four features does TCP have that UDP lacks?',
    'Connection-oriented setup, data sequencing, reliable delivery (ACK + retransmit), flow control (window size). (Ch.22 §22.2.2)'
  );
  ans(
    'EXAM-15',
    'Exam',
    'What is TCP flow control and how is it implemented?',
    'Prevents sender overwhelming receiver. Implemented via Window Size field — receiver tells sender how many bytes to send before waiting for ACK. Called "sliding window". (Ch.22 §22.2.1)'
  );
  ans(
    'EXAM-16',
    'Exam',
    'Why does UDP suit real-time apps like VoIP?',
    'Lost packets quickly become irrelevant; retransmission delay is worse than brief audio/video glitch. (Ch.22 §22.2.3)'
  );
  ans(
    'EXAM-17',
    'Exam',
    'Max ACLs per interface direction?',
    'One inbound ACL + one outbound ACL per interface. Same ACL may be applied to multiple interfaces. (Ch.23 §23.1.3)'
  );
  ans('EXAM-18', 'Exam', `Which keyword is equivalent to 0.0.0.0 ${prefixToWildcard(0)}?`, 'any');
  ans('EXAM-19', 'Exam', 'Which keyword matches exactly one IP with wildcard 0.0.0.0?', 'host <ip-addr>');
  ans(
    'EXAM-20',
    'Exam',
    'default ACE sequence start and increment?',
    'Starts at 10, increments by 10. (Ch.23 §23.2.1)'
  );
}

async function runLearn(topicArg: string, rl: readline.Interface): Promise<void> {
  const topic = topicArg.toLowerCase().trim();

  if (!topic || topic === 'help') {
    console.log(Ansi.cyan('\nAvailable learn topics:'));
    const topics: [string, string][] = [
      ['tcp-udp', 'TCP vs UDP — features, overhead, use cases (Ch.22)'],
      ['ports', 'Port numbers, IANA tiers, session multiplexing (Ch.22)'],
      ['standard', 'Standard ACLs — ACE order, implicit deny, wildcard, config (Ch.23)'],
      ['extended', 'Extended ACLs — proto/src/dst/port matching, config (Ch.24)'],
      ['placement', 'Where to apply ACLs inbound/outbound (Ch.23/24)'],
      ['editing', 'Deleting ACEs, inserting, resequencing (Ch.24 §24.3)'],
    ];
    for (const [t, desc] of topics) console.log(`  ${t.padEnd(12)} ${desc}`);
    return;
  }

  const eng = topology.engineering;
  const acc = topology.accounting;
  const srvA = topology.serverLanA;
  const srvB = topology.serverLanB;

  if (topic === 'tcp-udp') {
    banner('Ch.22 — TCP vs UDP');
    section('Layer 4 role');
    console.log('Layer 4 (Transport) delivers data to the correct APPLICATION on the');
    console.log('destination host. Layers 1–3 get the packet to the right device;');
    console.log('Layer 4 uses PORT NUMBERS to get it to the right process.');

    section('TCP — Transmission Control Protocol');
    console.log('  Connection-oriented: three-way handshake BEFORE data flows');
    console.log('    SYN → SYN-ACK → ACK');
    console.log('  Data sequencing: Sequence Number field reorders out-of-order segments');
    console.log('  Reliable delivery: every segment ACKed; retransmit on timeout');
    console.log('  Flow control: Window Size field — sliding window — limits burst size');
    console.log('  Connection termination: FIN → ACK → FIN → ACK (four-way)');
    console.log('  Header size: 20–60 bytes');

    section('UDP — User Datagram Protocol');
    console.log('  NOT connection-oriented: sender fires immediately, no handshake');
    console.log('  No sequencing, no ACK, no retransmission, no flow control');
    console.log('  Header: 8 bytes (src port, dst port, length, checksum)');
    console.log('  Checksum for error detection only — corrupt = discard and forget');

    section('TCP overhead (Ch.22 §22.2.3)');
    console.log('  Data overhead:       20–60 byte header vs UDP 8 bytes');
    console.log('  Processing overhead: connection state, ACK tracking, retransmit logic');
    console.log('  Time overhead:       three-way handshake latency before first byte');

    section('When TCP is preferred');
    const tcpServices = PORT_TABLE.filter((r) => r.transport === 'TCP' || r.transport === 'TCP/UDP');
    const examples = tcpServices
      .slice(0, 4)
      .map((r) => `${r.name}/${r.port}`)
      .join(', ');
    console.log(`  File transfer, web browsing, email — e.g. ${examples}`);
    console.log('  Data integrity > speed; minor latency from retransmit is acceptable.');

    section('When UDP is preferred');
    const udpServices = PORT_TABLE.filter((r) => r.transport === 'UDP');
    const udpEx = udpServices
      .slice(0, 3)
      .map((r) => `${r.name}/${r.port}`)
      .join(', ');
    console.log(`  Real-time: VoIP, video streaming, gaming — e.g. ${udpEx}`);
    console.log('  Simple query/response: DNS (small request, single response)');
    console.log('  App-layer reliability: TFTP ACKs every message itself → uses UDP');
    console.log('  Lost data quickly becomes irrelevant; retransmit delay is worse.');

    await pressEnter(rl);
  } else if (topic === 'ports') {
    banner('Ch.22 — Port Numbers & IANA Ranges');
    section('What is a port?');
    console.log('A 16-bit number (0–65535) addressing a message to a specific');
    console.log('application process on the destination host.');
    console.log('Source Port field = 16 bits → 2^16 = 65,536 possible ports.');

    section('Session multiplexing (Ch.22 §22.1.2)');
    console.log('Client selects a random ephemeral port as SOURCE for each session.');
    console.log('Five-tuple (src-IP, src-port, dst-IP, dst-port, L4-proto) uniquely');
    console.log('identifies each session — how Chrome and Firefox stay separate.');

    section('IANA Port Tiers (derived from protocols.getPortType())');
    for (const t of IANA_TIERS) {
      console.log(`  ${String(t.start).padEnd(6)}–${String(t.stop).padEnd(6)}  ${t.label}`);
      console.log(`         also called: ${t.alias}`);
    }

    section('Common protocols (from protocols.tcp/udp.portMap())');
    console.log(`  ${'Protocol'.padEnd(10)} ${'Transport'.padEnd(9)} ${'Port'.padEnd(6)} IANA tier`);
    rule();
    for (const row of PORT_TABLE) {
      const tier = protocols.getPortType(row.port);
      console.log(`  ${row.name.padEnd(10)} ${row.transport.padEnd(9)} ${String(row.port).padEnd(6)} ${tier}`);
    }
    await pressEnter(rl);
  } else if (topic === 'standard') {
    banner('Ch.23 — Standard ACLs');
    section('ACL fundamentals');
    console.log('An ordered list of ACEs (Access Control Entries) that filters packets');
    console.log('on a router interface. Logic: if-then-else, top-to-bottom.');
    console.log('  First matching ACE wins → action taken, rest skipped.');
    console.log(`  ${operationName(Operation.Permit)} = forward.  ${operationName(Operation.Deny)} = discard.`);

    section('Standard ACL — what it matches');
    console.log('  Source IP address ONLY. (Ch.23 §23.1.4)');

    section('Implicit deny (Ch.23 §23.1.2)');
    console.log('  Hidden final rule: deny any.');
    console.log('  Every ACL ends with this; it never appears in "show access-lists".');
    console.log(`  If no ACE matches → packet is ${Ansi.red(operationName(Operation.Deny))} silently.`);
    console.log('  Add explicit "permit any" to allow unmatched traffic through.');

    section('Shadowed rules (Ch.23 §23.1.1)');
    console.log('  More-specific ACEs MUST precede less-specific ones.');
    const engOctets = eng.network.split('.');
    const supernetNotation = `${engOctets[0]}.${engOctets[1]}.0.0 0.0.255.255`;
    console.log(`  E.g. deny ${eng.network} ${eng.wildcard}`);
    console.log(`  must come BEFORE permit ${supernetNotation}`);
    console.log(`  Otherwise ${engOctets[0]}.${engOctets[1]}.${engOctets[2]}.x is permitted before reaching the deny.`);

    section('Wildcard mask arithmetic (Ch.23 §23.2.1)');
    console.log("  Bit=0 → MUST match.   Bit=1 → ignore (don't care).");
    console.log('  Shortcut: subtract each subnet octet from 255.');
    for (const p of [24, 16, 28]) {
      console.log(`  /${p} → wildcard ${prefixToWildcard(p)}`);
    }

    section('ACL number ranges (from ReservedRanges)');
    console.log(`  ${AclKind.Standard}: ${rangeStr(AclKind.Standard)}`);
    console.log(`  ${AclKind.Extended}: ${rangeStr(AclKind.Extended)}`);

    section('Configuration syntax');
    console.log('  Numbered:');
    console.log('    access-list <number> {permit|deny} <src-ip> <wildcard>');
    console.log('    access-list <number> {permit|deny} host <ip>');
    console.log('    access-list <number> {permit|deny} any');
    console.log('  Named:');
    console.log('    ip access-list standard <name>');
    console.log('      [seq] {permit|deny} <src-ip> <wildcard>');
    console.log('  Apply: ip access-group {number|name} {in|out}');

    section('Sequence numbers');
    console.log('  First ACE = 10, default increment = 10. (Ch.23 §23.2.1)');
    console.log('  Gaps allow inserting ACEs between existing ones in named mode.');

    await pressEnter(rl);
  } else if (topic === 'extended') {
    banner('Ch.24 — Extended ACLs');
    section('What extended ACLs can match (Ch.24 §24.1.1)');
    console.log('  Protocol payload: tcp | udp | icmp | ospf | ip (matches ALL IPv4)');
    console.log('  Source IP + wildcard   (or host <ip> or any)');
    console.log('  Source TCP/UDP port    (optional)');
    console.log('  Destination IP + wildcard');
    console.log('  Destination TCP/UDP port (optional)');
    console.log('  ALL specified parameters must match — no partial match counts.');

    section('ACL number ranges');
    console.log(`  Extended numbered: ${rangeStr(AclKind.Extended)}`);

    section('Configuration syntax');
    console.log('  Numbered:');
    console.log('    access-list <100-199|2000-2699> {permit|deny} <proto>');
    console.log('      <src> <src-wc> [src-port] <dst> <dst-wc> [dst-port]');
    console.log('  Named:');
    console.log('    ip access-list extended <name|number>');
    console.log('      [seq] {permit|deny} <proto> <src> <src-wc> [src-port]');
    console.log('              <dst> <dst-wc> [dst-port]');

    section('Port operators (PortOperator type, Ch.24 §24.1.2)');
    const ops: [string, string][] = [
      ['eq <port>', 'equal to port'],
      ['gt <port>', 'greater than port (exclusive)'],
      ['lt <port>', 'less than port (exclusive)'],
      ['neq <port>', 'not equal to port'],
      ['range <a> <b>', 'a to b inclusive'],
    ];
    for (const [op, meaning] of ops) console.log(`  ${op.padEnd(20)} → ${meaning}`);

    section('src-port vs dst-port (Ch.24 §24.1.2)');
    console.log('  Client uses the service port as DESTINATION, ephemeral as SOURCE.');
    const http = PORT_TABLE.find((r) => r.port === 80);
    const ntp = PORT_TABLE.find((r) => r.port === 123);
    if (http) console.log(`  To block HTTP: filter dst eq ${http.port}  (NOT src eq ${http.port})`);
    if (ntp) console.log(`  To block NTP:  filter dst eq ${ntp.port}  protocol udp`);

    section('IOS port keywords (Ch.24 §24.1.2)');
    console.log('  Some well-known ports have IOS keywords:');
    console.log('  ftp-data=20  ftp=21  telnet=23  domain=53  bootps=67');
    console.log('  bootpc=68  tftp=69  www=80  ntp=123');

    await pressEnter(rl);
  } else if (topic === 'placement') {
    banner('Ch.23/24 — Where to Apply ACLs');
    section('Direction');
    console.log('  INBOUND  (ingress): filters packets AS THEY ENTER the interface.');
    console.log('  OUTBOUND (egress):  filters packets AS THEY LEAVE the interface.');
    console.log('  Limit: max 1 inbound + 1 outbound ACL per interface. (Ch.23 §23.1.3)');
    console.log('  Same ACL may be applied to multiple interfaces.');

    section('Standard ACL placement — close to DESTINATION (Ch.23 §23.2.1)');
    console.log('  Standard ACLs filter only by source IP.');
    console.log('  Placing near source risks blocking that source from ALL destinations,');
    console.log('  not just the one you want to protect.');
    console.log('  → Apply OUTBOUND on the interface connected to the protected LAN.');

    section('Extended ACL placement — close to SOURCE (Ch.24 §24.1.1)');
    console.log('  Extended ACLs precisely specify which traffic is blocked.');
    console.log('  Placing near source drops packets before they waste bandwidth');
    console.log('  traversing the network only to be denied at the last hop.');
    console.log('  → Apply INBOUND on the interface closest to the originating host.');

    section('Example: Ch.23 §23.2.1 scenario');
    console.log(`  Goal: block engineering (${eng.network}/${eng.prefix}) from Server LAN A.`);
    console.log(`  access-list 10 deny ${eng.network} ${eng.wildcard}`);
    console.log('  access-list 10 permit any');
    console.log('  → Applied OUTBOUND on R2 G0/0 (server side), NOT near the source.');

    await pressEnter(rl);
  } else if (topic === 'editing') {
    banner('Ch.24 §24.3 — Editing ACLs');
    section('Problem with numbered ACLs in global config mode');
    console.log('  "no access-list 1 deny ..." deletes the ENTIRE ACL, not just that ACE.');
    console.log('  You cannot surgically remove one ACE from global config mode.');

    section('Solution: named ACL config mode (Ch.24 §24.3.1)');
    console.log('  Works for BOTH named and numbered ACLs:');
    console.log('    ip access-list standard 1   ← enter named mode for numbered ACL');
    console.log('      no 30                      ← delete only seq 30');
    console.log(`      30 deny ${srvB.network} ${srvB.wildcard}  ← insert new ACE at seq 30`);

    section('Resequencing (Ch.24 §24.3.2)');
    console.log('  When no gap exists between seq numbers, resequence:');
    console.log('  ip access-list resequence <id|name> <start> <increment>');
    console.log('  Example: ip access-list resequence 101 10 10');
    console.log('  → Renumbers ACEs 10, 20, 30, … creating space for insertions.');
    console.log('  E.g. ACEs at 10, 18, 19, 20 → become 10, 20, 30, 40.');

    section('Sequence number defaults (Ch.23 §23.2.1)');
    console.log('  First ACE = 10, each subsequent += 10 by default.');
    console.log('  In named mode you can specify your own seq number explicitly.');

    await pressEnter(rl);
  } else {
    console.log(Ansi.yellow(`Unknown topic "${topic}". Type: learn help`));
  }
}

interface DrillCard {
  question: string;
  answer: string;
  hint?: string;
}

function buildDrillDeck(topic: string): DrillCard[] {
  const cards: DrillCard[] = [];

  if (topic === 'wildcards' || topic === 'all') {
    const prefixes = [8, 16, 20, 24, 25, 27, 28, 30];
    for (const p of prefixes) {
      const wc = prefixToWildcard(p);
      cards.push({ question: `Wildcard mask for /${p}?`, answer: wc, hint: 'Subtract each subnet octet from 255' });
      cards.push({ question: `Wildcard ${wc} — which CIDR prefix?`, answer: `/${p}` });
    }
    for (const c of DRILL_CASES) {
      const live = new WildcardMatcher(c.target, c.wc).match(c.src).isMatch;
      if (live !== c.expected) continue;
      const result = live ? operationName(Operation.Permit) : operationName(Operation.Deny);
      cards.push({
        question: `Packet src ${c.src} against ACE target ${c.target} wildcard ${c.wc} — match?`,
        answer: `${live ? 'Yes (match)' : 'No (no match)'} → ${result}`,
        hint: 'Wildcard 0 = must match, 1 = ignore',
      });
    }
  }

  if (topic === 'ports' || topic === 'all') {
    for (const row of PORT_TABLE) {
      cards.push({ question: `Port number for ${row.name} (${row.transport})?`, answer: String(row.port) });
      cards.push({ question: `Port ${row.port}/${row.transport.toLowerCase()} — which protocol?`, answer: row.name });
      const tier = protocols.getPortType(row.port);
      cards.push({
        question: `Port ${row.port} — IANA tier? (${IANA_TIERS.map((t) => t.label).join(' / ')})`,
        answer: tier,
      });
    }
  }

  if (topic === 'ranges' || topic === 'all') {
    for (const [kind, ranges] of Object.entries(ReservedRanges) as [AclKind, AclRange[]][]) {
      cards.push({ question: `All numbered ACL ranges for ${kind}?`, answer: rangeStr(kind) });
      for (const r of ranges) {
        const mid = midpoint(r);
        cards.push({
          question: `ACL number ${mid} — ${AclKind.Standard} or ${AclKind.Extended}?`,
          answer: inferKindFromNumber(mid),
          hint: `Standard: ${rangeStr(AclKind.Standard)}  Extended: ${rangeStr(AclKind.Extended)}`,
        });
      }
    }
    for (const t of IANA_TIERS) {
      cards.push({ question: `IANA "${t.label}" tier — port range?`, answer: `${t.start}–${t.stop}`, hint: t.alias });
    }
  }

  if (topic === 'operators' || topic === 'all') {
    const operatorCases: Array<{ cond: PortCondition; testPort: number; expected: boolean }> = [
      { cond: { op: 'eq', port: 443 }, testPort: 443, expected: true },
      { cond: { op: 'eq', port: 443 }, testPort: 80, expected: false },
      { cond: { op: 'gt', port: 1023 }, testPort: 8080, expected: true },
      { cond: { op: 'gt', port: 1023 }, testPort: 80, expected: false },
      { cond: { op: 'lt', port: 1024 }, testPort: 80, expected: true },
      { cond: { op: 'lt', port: 1024 }, testPort: 8080, expected: false },
      { cond: { op: 'neq', port: 23 }, testPort: 22, expected: true },
      { cond: { op: 'neq', port: 23 }, testPort: 23, expected: false },
      { cond: { op: 'range', portA: 80, portB: 100 }, testPort: 90, expected: true },
      { cond: { op: 'range', portA: 80, portB: 100 }, testPort: 443, expected: false },
    ];
    for (const c of operatorCases) {
      const pm = new PortMatcher(c.cond);
      const live = pm.matches(c.testPort);
      if (live !== c.expected) continue;
      cards.push({
        question: `Port operator "${pm.toString()}" — does port ${c.testPort} match?`,
        answer: live ? 'Yes' : 'No',
        hint: 'eq=equal  gt=greater  lt=less  neq=not-equal  range=inclusive',
      });
    }
    const meanings: [string, string][] = [
      ['eq 443', 'equal to 443'],
      ['gt 1023', 'greater than 1023 (not including 1023)'],
      ['lt 1024', 'less than 1024 (not including 1024)'],
      ['neq 23', 'not equal to 23'],
      ['range 80 100', '80 to 100 inclusive'],
    ];
    for (const [op, meaning] of meanings) {
      cards.push({ question: `What does port operator "${op}" mean?`, answer: meaning });
    }
  }

  for (let i = cards.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = cards[i]!;
    cards[i] = cards[j]!;
    cards[j] = tmp;
  }
  return cards;
}

async function runDrill(topicArg: string, rl: readline.Interface): Promise<void> {
  const valid = ['wildcards', 'ports', 'ranges', 'operators', 'all'];
  const topic = topicArg.toLowerCase().trim() || 'all';

  if (!valid.includes(topic)) {
    console.log(Ansi.yellow(`\nUnknown drill topic. Choose: ${valid.join(' | ')}`));
    return;
  }

  const cards = buildDrillDeck(topic);
  if (!cards.length) {
    console.log(Ansi.yellow('No cards for that topic.'));
    return;
  }

  banner(`Drill — ${topic}  (${cards.length} cards)`);
  console.log(Ansi.cyan('Type your answer + Enter. "skip" to reveal. "quit" to stop.\n'));

  let correct = 0,
    attempted = 0;

  for (const [i, card] of cards.entries()) {
    section(`Card ${i + 1} / ${cards.length}`);
    console.log(Ansi.bold(`Q: ${card.question}`));
    if (card.hint) console.log(Ansi.cyan(`   Hint: ${card.hint}`));

    const input = (await ask(rl, '  A: ')).trim();
    attempted++;

    if (input.toLowerCase() === 'quit') break;
    if (input === '' || input.toLowerCase() === 'skip') {
      console.log(Ansi.yellow(`  Answer: ${card.answer}`));
    } else if (input.toLowerCase() === card.answer.toLowerCase()) {
      console.log(Ansi.green('  ✓ Correct!'));
      correct++;
    } else {
      console.log(Ansi.red('  ✗ Incorrect.'));
      console.log(Ansi.yellow(`  Answer: ${card.answer}`));
    }
  }

  rule();
  const pct = Math.round((correct / Math.max(1, attempted)) * 100);
  console.log(`\nScore: ${Ansi.green(String(correct))} / ${attempted}  (${pct}%)\n`);
}

interface TestCase {
  packet: Packet;
  label: string;
}
interface Lab {
  id: number;
  title: string;
  chapter: string;
  scenario: string;
  task: string;
  buildAcl: () => AccessList;
  aclId: AclId;
  tests: TestCase[];
  solutionLines: string[];
  explanation: string;
}

function buildLabs(): Lab[] {
  const eng = topology.engineering;
  const acc = topology.accounting;
  const srvA = topology.serverLanA;
  const srvB = topology.serverLanB;

  const engHostA = eng.hosts[0] ?? eng.gateway;
  const engHostB = eng.hosts[1] ?? eng.gateway;
  const accHostA = acc.hosts[0] ?? acc.gateway;
  const srvAHost = srvA.hosts[0] ?? srvA.gateway;
  const srvBHost = srvB.hosts[0] ?? srvB.gateway;
  const marthaIp = eng.hosts[1] ?? eng.hosts[0] ?? eng.gateway;
  const bobIp = acc.hosts[1] ?? acc.hosts[0] ?? acc.gateway;
  const external = topology.externalHost;

  const httpsPort = PORT_TABLE.find((r) => r.name === 'HTTPS')!.port;
  const tftpPort = PORT_TABLE.find((r) => r.name === 'TFTP')!.port;
  const ntpPort = PORT_TABLE.find((r) => r.name === 'NTP')!.port;
  const httpPort = PORT_TABLE.find((r) => r.port === 80)!.port;

  const lab1: Lab = {
    id: 1,
    title: 'Standard Numbered ACL — Deny Subnet, Permit All',
    chapter: 'Ch.23 §23.2.1',
    scenario: `Engineering (${eng.network}/${eng.prefix}) must be blocked from Server LAN A. All other hosts permitted.`,
    task: [
      'Study the ACL shown below.',
      'For each test packet, predict Permit or Deny BEFORE the result is revealed.',
      'Notice ACE order and why the implicit deny catches the last packet.',
    ].join('\n  '),
    buildAcl: () => {
      const acl = new AccessList();
      acl.addStandard(10, { op: Operation.Deny, srcIp: eng.network, wildcardMask: eng.wildcard });
      acl.addStandard(10, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      return acl;
    },
    aclId: 10,
    tests: [
      { packet: { protocol: 'ip', srcIp: engHostA, dstIp: srvAHost }, label: 'Engineering host → Server LAN A' },
      { packet: { protocol: 'ip', srcIp: accHostA, dstIp: srvAHost }, label: 'Accounting host → Server LAN A' },
      { packet: { protocol: 'ip', srcIp: external, dstIp: srvAHost }, label: 'External host → Server LAN A' },
    ],
    solutionLines: [`access-list 10 deny ${eng.network} ${eng.wildcard}`, 'access-list 10 permit any'],
    explanation: `ACE seq 10 denies ${eng.network}/${eng.prefix}. ACE seq 20 is "permit any". ${engHostA} matches seq 10 and is denied. Standard ACL → apply OUTBOUND on the server-side interface (close to destination).`,
  };

  const lab2: Lab = {
    id: 2,
    title: 'Standard Named ACL — Deny Specific Hosts',
    chapter: 'Ch.23 §23.2.2',
    scenario: `Martha (${marthaIp}) and Bob (${bobIp}) blocked from all server LANs.`,
    task: 'Examine ACL "BLOCK_HOSTS". Predict each result. Note wildcard 0.0.0.0 = host match.',
    buildAcl: () => {
      const id = 'BLOCK_HOSTS';
      const acl = new AccessList();
      acl.addStandard(id, { op: Operation.Deny, srcIp: marthaIp, wildcardMask: '0.0.0.0' });
      acl.addStandard(id, { op: Operation.Deny, srcIp: bobIp, wildcardMask: '0.0.0.0' });
      acl.addStandard(id, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      return acl;
    },
    aclId: 'BLOCK_HOSTS',
    tests: [
      { packet: { protocol: 'ip', srcIp: marthaIp, dstIp: srvAHost }, label: `Martha (${marthaIp}) → Server LAN A` },
      { packet: { protocol: 'ip', srcIp: bobIp, dstIp: srvBHost }, label: `Bob (${bobIp}) → Server LAN B` },
      { packet: { protocol: 'ip', srcIp: engHostB, dstIp: srvAHost }, label: 'Other engineer → Server LAN A' },
    ],
    solutionLines: [
      'ip access-list standard BLOCK_HOSTS',
      `  deny host ${marthaIp}`,
      `  deny host ${bobIp}`,
      '  permit any',
    ],
    explanation:
      '"host <ip>" is equivalent to wildcard 0.0.0.0 — matches exactly one address. ACL applied INBOUND on R2 G0/2 filters packets destined for both server LANs in one rule.',
  };

  const lab3: Lab = {
    id: 3,
    title: 'Shadowed Rule — ACE Order Matters',
    chapter: 'Ch.23 §23.1.1',
    scenario: 'A misconfigured ACL has the broad permit BEFORE the specific deny.',
    task: `Observe that ${engHostA} is PERMITTED despite the deny ACE existing.`,
    buildAcl: () => {
      const acl = new AccessList();
      acl.addStandard(20, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      acl.addStandard(20, { op: Operation.Deny, srcIp: eng.network, wildcardMask: eng.wildcard });
      return acl;
    },
    aclId: 20,
    tests: [
      {
        packet: { protocol: 'ip', srcIp: engHostA, dstIp: srvAHost },
        label: 'Engineering host (should be denied but is permitted by shadowed config!)',
      },
      { packet: { protocol: 'ip', srcIp: accHostA, dstIp: srvAHost }, label: 'Accounting host' },
    ],
    solutionLines: [
      `access-list 20 deny ${eng.network} ${eng.wildcard}   ← specific first`,
      'access-list 20 permit any                              ← broad second',
    ],
    explanation:
      'The "permit any" at seq 10 matches ALL packets. The deny at seq 20 is a shadowed rule — it will never be evaluated. Always configure more specific rules FIRST.',
  };

  const lab4: Lab = {
    id: 4,
    title: 'Extended Numbered ACL — Permit HTTPS Only',
    chapter: 'Ch.24 §24.1.2',
    scenario: `Engineering (${eng.network}/${eng.prefix}) may access Server LAN A (${srvA.network}/${srvA.prefix}) only via HTTPS (TCP/${httpsPort}). All other TCP denied.`,
    task: 'Examine extended ACL 101. Predict each result — note protocol and dst port.',
    buildAcl: () => {
      const acl = new AccessList();
      acl.addExtended(101, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: eng.network,
        srcWildcard: eng.wildcard,
        dstIp: srvA.network,
        dstWildcard: srvA.wildcard,
        dstPort: { op: 'eq', port: httpsPort },
      });
      acl.addExtended(101, {
        op: Operation.Deny,
        protocol: 'ip',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      return acl;
    },
    aclId: 101,
    tests: [
      {
        packet: { protocol: 'tcp', srcIp: engHostA, dstIp: srvAHost, dstPort: httpsPort },
        label: `Engineering → Server LAN A TCP/${httpsPort} (HTTPS)`,
      },
      {
        packet: { protocol: 'tcp', srcIp: engHostA, dstIp: srvAHost, dstPort: httpPort },
        label: `Engineering → Server LAN A TCP/${httpPort} (HTTP)`,
      },
      { packet: { protocol: 'udp', srcIp: engHostA, dstIp: srvAHost }, label: 'Engineering → Server LAN A UDP (any)' },
    ],
    solutionLines: [
      `access-list 101 permit tcp ${eng.network} ${eng.wildcard} ${srvA.network} ${srvA.wildcard} eq ${httpsPort}`,
      'access-list 101 deny ip any any',
    ],
    explanation: `Filter on DESTINATION port ${httpsPort} — the port the server listens on. Extended ACL → apply INBOUND on R1 G0/0 (close to engineering, the source). (Ch.24 §24.1.1)`,
  };

  const lab5: Lab = {
    id: 5,
    title: 'Extended Named ACL — Deny TFTP from Accounting',
    chapter: 'Ch.24 §24.2',
    scenario: `Accounting (${acc.network}/${acc.prefix}) may not use TFTP (UDP/${tftpPort}) to any destination.`,
    task: `Examine "NO_TFTP". Note: protocol=udp + dst eq ${tftpPort}. Predict each result.`,
    buildAcl: () => {
      const id = 'NO_TFTP';
      const acl = new AccessList();
      acl.addExtended(id, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: acc.network,
        srcWildcard: acc.wildcard,
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: tftpPort },
      });
      acl.addExtended(id, {
        op: Operation.Permit,
        protocol: 'ip',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      return acl;
    },
    aclId: 'NO_TFTP',
    tests: [
      {
        packet: { protocol: 'udp', srcIp: accHostA, dstIp: srvAHost, dstPort: tftpPort },
        label: `Accounting → Server UDP/${tftpPort} (TFTP)`,
      },
      {
        packet: { protocol: 'udp', srcIp: accHostA, dstIp: srvAHost, dstPort: ntpPort },
        label: `Accounting → Server UDP/${ntpPort} (NTP)`,
      },
      {
        packet: { protocol: 'tcp', srcIp: accHostA, dstIp: srvAHost, dstPort: httpPort },
        label: `Accounting → Server TCP/${httpPort} (HTTP)`,
      },
    ],
    solutionLines: [
      'ip access-list extended NO_TFTP',
      `  deny udp ${acc.network} ${acc.wildcard} any eq ${tftpPort}`,
      '  permit ip any any',
    ],
    explanation: `Protocol must be "udp" to use dst port condition. UDP/${tftpPort} from accounting is denied; all other traffic permitted by "permit ip any any". Extended ACL → close to the source (accounting LAN).`,
  };

  const lab6: Lab = {
    id: 6,
    title: 'Extended Named ACL — ICMP-only Between Server LANs',
    chapter: 'Ch.24 §24.2',
    scenario: `Only ICMP is permitted between Server LAN A (${srvA.network}/${srvA.prefix}) and Server LAN B (${srvB.network}/${srvB.prefix}).`,
    task: 'Examine "ICMP_ONLY". Protocol field matters — icmp vs ip vs tcp.',
    buildAcl: () => {
      const id = 'ICMP_ONLY';
      const acl = new AccessList();
      acl.addExtended(id, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: srvA.network,
        srcWildcard: srvA.wildcard,
        dstIp: srvB.network,
        dstWildcard: srvB.wildcard,
      });
      acl.addExtended(id, {
        op: Operation.Deny,
        protocol: 'ip',
        srcIp: srvA.network,
        srcWildcard: srvA.wildcard,
        dstIp: srvB.network,
        dstWildcard: srvB.wildcard,
      });
      acl.addExtended(id, {
        op: Operation.Permit,
        protocol: 'ip',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      return acl;
    },
    aclId: 'ICMP_ONLY',
    tests: [
      { packet: { protocol: 'icmp', srcIp: srvAHost, dstIp: srvBHost }, label: 'Server LAN A → LAN B (ICMP / ping)' },
      { packet: { protocol: 'tcp', srcIp: srvAHost, dstIp: srvBHost }, label: 'Server LAN A → LAN B (TCP)' },
      { packet: { protocol: 'udp', srcIp: srvAHost, dstIp: srvBHost }, label: 'Server LAN A → LAN B (UDP)' },
      {
        packet: { protocol: 'tcp', srcIp: engHostA, dstIp: srvBHost },
        label: 'Engineering → Server LAN B (TCP) — not filtered here',
      },
    ],
    solutionLines: [
      'ip access-list extended ICMP_ONLY',
      `  permit icmp ${srvA.network} ${srvA.wildcard} ${srvB.network} ${srvB.wildcard}`,
      `  deny ip ${srvA.network} ${srvA.wildcard} ${srvB.network} ${srvB.wildcard}`,
      '  permit ip any any',
    ],
    explanation:
      '"ip" as protocol matches ALL IPv4 regardless of encapsulated proto. "icmp" matches only ICMP. Order: permit icmp first, then deny ip catches TCP/UDP between the LANs. The final permit ip any any passes all other traffic.',
  };

  return [lab1, lab2, lab3, lab4, lab5, lab6];
}

async function runPractice(nArg: string, rl: readline.Interface): Promise<void> {
  const labs = buildLabs();
  let lab: Lab | undefined;

  if (nArg) {
    const n = parseInt(nArg, 10);
    lab = labs.find((l) => l.id === n);
    if (!lab) {
      console.log(Ansi.yellow(`No lab ${nArg}. Choose 1–${labs.length}.`));
      return;
    }
  } else {
    banner('Practice Lab Menu');
    labs.forEach((l) => console.log(`  ${l.id}. [${l.chapter}] ${l.title}`));
    const choice = (await ask(rl, '\nSelect lab number: ')).trim();
    lab = labs.find((l) => l.id === parseInt(choice, 10));
    if (!lab) {
      console.log(Ansi.yellow('Invalid selection.'));
      return;
    }
  }

  banner(`Lab ${lab.id}: ${lab.title}`);
  console.log(Ansi.cyan(`Chapter: ${lab.chapter}`));
  section('Scenario');
  console.log(`  ${lab.scenario}`);
  section('Task');
  console.log(`  ${lab.task}`);

  const acl = lab.buildAcl();
  section('ACL configuration (show access-lists)');
  console.log(acl.showAcl(lab.aclId));

  section('Packet evaluation — predict before revealing');
  let correct = 0;
  for (const [i, t] of lab.tests.entries()) {
    const actual = silently(() => acl.validate(t.packet, lab!.aclId));
    const p = t.packet;
    const portInfo = p.dstPort !== undefined ? ` dst:${p.dstPort}` : p.srcPort !== undefined ? ` src:${p.srcPort}` : '';
    console.log(Ansi.bold(`\n  Packet ${i + 1}: ${t.label}`));
    console.log(`  ${p.srcIp} → ${p.dstIp}  [${p.protocol}${portInfo}]`);

    const guess = (await ask(rl, Ansi.cyan('  Your prediction (permit/deny): '))).trim().toLowerCase();
    const guessedPermit = guess.startsWith('p');
    const actualPermit = actual === operationName(Operation.Permit);
    const colour = actualPermit ? Ansi.green : Ansi.red;

    console.log(colour(`  Result: ${actual}`));
    if (guessedPermit === actualPermit) {
      console.log(Ansi.green('  ✓ Correct prediction!'));
      correct++;
    } else {
      console.log(Ansi.red('  ✗ Incorrect prediction.'));
    }
  }

  section('Solution');
  lab.solutionLines.forEach((l) => console.log(Ansi.bold(`  ${l}`)));
  section('Explanation');
  console.log(`  ${lab.explanation}`);
  rule();
  console.log(`\nPrediction score: ${Ansi.green(String(correct))} / ${lab.tests.length}\n`);
  await pressEnter(rl);
}

interface ExamQuestion {
  q: string;
  choices?: string[];
  correctIndex?: number;
  fillAnswer?: string;
  validate?: { acl: AccessList; aclId: AclId; packet: Packet };
}

function buildExam(): ExamQuestion[] {
  const qs: ExamQuestion[] = [];
  const permitStr = operationName(Operation.Permit);
  const denyStr = operationName(Operation.Deny);

  qs.push({
    q: 'A packet matches no ACE in an applied ACL. What happens?',
    choices: [
      'A) The packet is forwarded (router default behaviour)',
      `B) The packet is discarded by the implicit ${denyStr}`,
      'C) The ACL is skipped and the packet is routed normally',
      'D) The router logs an error and drops the packet',
    ],
    correctIndex: 1,
  });
  qs.push({
    q: 'Standard ACLs filter packets based on which field?',
    choices: [
      'A) Destination IP + TCP/UDP port',
      'B) Source MAC address',
      'C) Source IP address only',
      'D) Protocol type (TCP/UDP/ICMP)',
    ],
    correctIndex: 2,
  });
  qs.push({
    q: 'Extended ACLs should be placed as close to the ___ as possible.',
    choices: [
      'A) Destination — to minimise the number of interfaces the ACL touches',
      'B) Source — to discard unwanted packets before they consume bandwidth',
      'C) Core router — for centralised policy enforcement',
      'D) Border router — to inspect all external traffic',
    ],
    correctIndex: 1,
  });
  qs.push({
    q: 'In a wildcard mask, a bit value of 0 means:',
    choices: [
      'A) Ignore this bit — it does not need to match',
      'B) This bit MUST match the ACE target address',
      'C) This bit is reserved for future use',
      'D) Always deny packets with this bit set',
    ],
    correctIndex: 1,
  });

  const midExt = midpoint(ReservedRanges[AclKind.Extended][0]!);
  qs.push({
    q: `ACL number ${midExt} is which type? (Standard ranges: ${rangeStr(AclKind.Standard)})`,
    choices: [
      `A) ${AclKind.Standard}`,
      `B) ${AclKind.Extended}`,
      'C) Invalid — not in any reserved range',
      'D) Named ACL only',
    ],
    correctIndex: 1,
  });

  const httpRow = PORT_TABLE.find((r) => r.name === 'HTTP')!;
  qs.push({ q: `Fill in: ${httpRow.name} uses ${httpRow.transport} port ___`, fillAnswer: String(httpRow.port) });
  qs.push({ q: `Fill in: Wildcard mask for /28 is ___`, fillAnswer: prefixToWildcard(28) });
  qs.push({
    q: 'TCP three-way handshake sequence?',
    choices: ['A) SYN → ACK → SYN', 'B) SYN → SYN-ACK → ACK', 'C) SYN-ACK → SYN → ACK', 'D) ACK → SYN → SYN-ACK'],
    correctIndex: 1,
  });

  const eph = IANA_TIERS.find((t) => t.start === 49152)!;
  qs.push({ q: `Fill in: IANA ephemeral port range is ___ to ___`, fillAnswer: `${eph.start} - ${eph.stop}` });

  const examAcl = new AccessList();
  examAcl.addStandard(99, { op: Operation.Deny, srcIp: examScenario.network, wildcardMask: examScenario.wildcard });
  examAcl.addStandard(99, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
  const examPacket: Packet = { protocol: 'ip', srcIp: examScenario.testSrc, dstIp: examScenario.testDst };
  const examExpected = silently(() => examAcl.validate(examPacket, 99));
  qs.push({
    q: [
      `Live ACL 99:`,
      `  10 ${denyStr}   ${examScenario.network} ${examScenario.wildcard}`,
      `  20 ${permitStr} any`,
      ``,
      `Packet: src ${examScenario.testSrc} → ${examScenario.testDst}  [ip]`,
      `What is the result? (${permitStr} / ${denyStr})`,
    ].join('\n'),
    fillAnswer: examExpected,
    validate: { acl: examAcl, aclId: 99, packet: examPacket },
  });
  qs.push({
    q: 'Which of the following does UDP provide? (select one)',
    choices: [
      'A) Reliable delivery with acknowledgements and retransmission',
      'B) Port-based addressing and session multiplexing',
      'C) Flow control via Window Size field',
      'D) Connection-oriented communication',
    ],
    correctIndex: 1,
  });
  qs.push({
    q: 'What is a "shadowed rule" in an ACL?',
    choices: [
      'A) A hidden ACE added automatically by Cisco IOS',
      'B) The implicit deny at the end of every ACL',
      'C) An ACE that can never match because a preceding less-specific ACE already covers it',
      'D) An ACE applied only to inbound traffic',
    ],
    correctIndex: 2,
  });

  return qs;
}

async function runExam(rl: readline.Interface): Promise<void> {
  const questions = buildExam();
  banner(`CCNA Exam Simulation  (${questions.length} questions, ~15 min)`);
  console.log(Ansi.yellow('This is timed. Questions are graded automatically.\n'));

  const startMs = Date.now();
  let score = 0;

  for (const [i, q] of questions.entries()) {
    section(`Question ${i + 1} / ${questions.length}`);
    console.log(Ansi.bold(q.q));

    if (q.choices) {
      q.choices.forEach((c) => console.log(`  ${c}`));
      const raw = (await ask(rl, '\n  Your answer (A/B/C/D): ')).trim().toUpperCase();
      const idx = ['A', 'B', 'C', 'D'].indexOf(raw);
      if (idx === q.correctIndex) {
        console.log(Ansi.green('  ✓ Correct'));
        score++;
      } else {
        const correct = ['A', 'B', 'C', 'D'][q.correctIndex!]!;
        console.log(Ansi.red(`  ✗ Incorrect. Answer: ${correct}) ${q.choices[q.correctIndex!]!.slice(3)}`));
      }
    } else if (q.fillAnswer !== undefined) {
      const raw = (await ask(rl, '  Your answer: ')).trim();
      const expected = q.fillAnswer;
      const match =
        raw.toLowerCase() === expected.toLowerCase() ||
        raw.toLowerCase().startsWith(expected.toLowerCase().split('–')[0]!.toLowerCase());
      if (match) {
        console.log(Ansi.green('  ✓ Correct'));
        score++;
      } else {
        console.log(Ansi.red(`  ✗ Incorrect. Answer: ${expected}`));
      }
    }
  }

  const elapsedSec = Math.round((Date.now() - startMs) / 1000);
  const pct = Math.round((score / questions.length) * 100);
  rule();
  console.log(Ansi.bold('\nExam complete!'));
  console.log(`Score:   ${Ansi.green(String(score))} / ${questions.length}  (${pct}%)`);
  console.log(`Time:    ${Math.floor(elapsedSec / 60)}m ${elapsedSec % 60}s`);
  if (pct >= 85) console.log(Ansi.green('  Excellent — CCNA-ready on this material!'));
  else if (pct >= 70) console.log(Ansi.yellow('  Good — review the topics you missed.'));
  else console.log(Ansi.red('  Keep studying — use "learn" and "drill" to reinforce.'));
  console.log();
  await pressEnter(rl);
}

function printAnswers(): void {
  banner('Answer Key');
  let currentSection = '';
  for (const a of ANSWER_KEY) {
    if (a.section !== currentSection) {
      section(a.section);
      currentSection = a.section;
    }
    console.log(Ansi.bold(`  [${a.id}] ${a.question}`));
    console.log(`        ${a.answer}\n`);
  }
}

function saveAnswers(outPath: string): void {
  const lines: string[] = ['ACL LEARNING — ANSWER KEY', '='.repeat(W), ''];
  let currentSection = '';
  for (const a of ANSWER_KEY) {
    if (a.section !== currentSection) {
      lines.push('', `── ${a.section} ─`.padEnd(W, '─'), '');
      currentSection = a.section;
    }
    lines.push(`[${a.id}] ${a.question}`, `      ${a.answer}`, '');
  }
  fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
  console.log(Ansi.green(`\nAnswer key saved → ${outPath}\n`));
}

function printHelp(): void {
  section('Commands');
  const cmds: [string, string][] = [
    ['learn <topic>', 'Concept walkthrough. "learn help" for topic list'],
    ['drill <topic>', 'Flashcard memorisation. "drill help" for topics'],
    ['practice [n]', 'Guided lab 1–6. Omit n for menu'],
    ['exam', 'Timed CCNA-style mixed question session'],
    ['answers', 'Reveal full answer key (hidden by default)'],
    ['answers save', 'Write answer key to answer-key.txt'],
    ['topology', "Show this session's generated network topology"],
    ['sandbox', 'Free CiscoAclCli shell (cli.ts)'],
    ['help', 'Show this menu'],
    ['exit', 'Quit'],
  ];
  for (const [cmd, desc] of cmds) console.log(`  ${Ansi.bold(cmd.padEnd(18))} ${desc}`);
  console.log();
}

function printTopology(): void {
  banner('Session Topology');
  console.log(Ansi.cyan(`  Seed: ${SEED}  (replay with --seed=${SEED})\n`));
  const rows: [string, string][] = [
    [
      'Engineering',
      `${topology.engineering.network}/${topology.engineering.prefix}  gw: ${topology.engineering.gateway} (${topology.engineering.gatewayStyle})`,
    ],
    [
      'Accounting',
      `${topology.accounting.network}/${topology.accounting.prefix}  gw: ${topology.accounting.gateway} (${topology.accounting.gatewayStyle})`,
    ],
    [
      'Server LAN A',
      `${topology.serverLanA.network}/${topology.serverLanA.prefix}  gw: ${topology.serverLanA.gateway} (${topology.serverLanA.gatewayStyle})`,
    ],
    [
      'Server LAN B',
      `${topology.serverLanB.network}/${topology.serverLanB.prefix}  gw: ${topology.serverLanB.gateway} (${topology.serverLanB.gatewayStyle})`,
    ],
    ['External host', topology.externalHost],
    ['Exam block', `${examScenario.network}/${examScenario.prefix}  test src: ${examScenario.testSrc}`],
  ];
  for (const [label, value] of rows) console.log(`  ${Ansi.bold(label.padEnd(14))} ${value}`);
  console.log();
}

async function main(): Promise<void> {
  buildAnswerKey();

  banner('ACL Learning Console');
  console.log(Ansi.cyan('  Chapters 22–24 · TCP/UDP · Standard ACLs · Extended ACLs'));
  console.log(Ansi.cyan(`  Session seed: ${SEED}  (replay: --seed=${SEED})`));
  console.log(Ansi.cyan('  Type "help" to begin.\n'));

  const rl = makeRl();

  const loop = async (): Promise<void> => {
    const raw = (await ask(rl, Ansi.bold('acl> '))).trim();
    if (!raw) return loop();

    const [cmd, ...rest] = raw.split(/\s+/);
    const arg = rest.join(' ');

    switch (cmd?.toLowerCase()) {
      case 'learn':
        await runLearn(arg, rl);
        break;
      case 'drill':
        await runDrill(arg, rl);
        break;
      case 'practice':
        await runPractice(arg, rl);
        break;
      case 'exam':
        await runExam(rl);
        break;
      case 'answers':
        if (arg === 'save') saveAnswers(path.join(process.cwd(), 'answer-key.txt'));
        else printAnswers();
        break;
      case 'topology':
        printTopology();
        break;
      case 'sandbox':
        rl.close();
        const { main: cliMain } = await import('./types/cli.js');
        cliMain();
        return;
      case 'help':
        printHelp();
        break;
      case 'exit':
      case 'quit':
        console.log(Ansi.cyan('\nGoodbye!\n'));
        rl.close();
        process.exit(0);
      default:
        console.log(Ansi.yellow(`Unknown command "${cmd}". Type "help".`));
    }

    return loop();
  };

  await loop();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
