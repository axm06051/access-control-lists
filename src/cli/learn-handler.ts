import * as readline from 'node:readline';
import { Ansi } from '@/domains/acl';
import { banner, section, rule, pressEnter } from './commands';

const W = 66;

export async function runLearn(topicArg: string, rl: readline.Interface, context: any): Promise<void> {
  let topic = topicArg.toLowerCase().trim();

  const topics: [string, string][] = [
    ['tcp-udp', 'TCP vs UDP - features, overhead, use cases'],
    ['ports', 'Port numbers, IANA tiers, session multiplexing'],
    ['standard', 'Standard ACLs - ACE order, implicit deny, wildcard, config'],
    ['extended', 'Extended ACLs - proto/src/dst/port matching, config'],
    ['placement', 'Where to apply ACLs inbound/outbound'],
    ['editing', 'Deleting ACEs, inserting, resequencing'],
  ];

  if (!topic || topic === 'help') {
    console.log(Ansi.yellow('\n[!] Incomplete command. Choose a topic:\n'));
    for (const [t, desc] of topics) console.log(`  ${t.padEnd(12)} ${desc}`);
    return;
  }

  const matches = topics.filter(([t]) => t.startsWith(topic));
  if (matches.length === 1 && matches[0]) {
    topic = matches[0][0];
  } else if (matches.length === 0) {
    console.log(Ansi.yellow(`\nUnknown topic "${topicArg}". Type "learn help".\n`));
    return;
  }

  const { topology, PORT_TABLE, IANA_TIERS, prefixToWildcard } = context;
  const eng = topology.engineering;
  const acc = topology.accounting;
  const srvA = topology.serverLanA;

  if (topic === 'tcp-udp') {
    banner('TCP vs UDP');
    section('Layer 4 role');
    console.log('Layer 4 (Transport) delivers data to the correct APPLICATION on the');
    console.log('destination host. Layers 1-3 get the packet to the right device;');
    console.log('Layer 4 uses PORT NUMBERS to get it to the right process.');

    section('TCP - Transmission Control Protocol');
    console.log('  Connection-oriented: three-way handshake BEFORE data flows');
    console.log('    SYN -> SYN-ACK -> ACK');
    console.log('  Data sequencing: Sequence Number field reorders out-of-order segments');
    console.log('  Reliable delivery: every segment ACKed; retransmit on timeout');
    console.log('  Flow control: Window Size field - sliding window - limits burst size');
    console.log('  Connection termination: FIN -> ACK -> FIN -> ACK (four-way)');
    console.log('  Header size: 20-60 bytes');

    section('UDP - User Datagram Protocol');
    console.log('  NOT connection-oriented: sender fires immediately, no handshake');
    console.log('  No sequencing, no ACK, no retransmission, no flow control');
    console.log('  Header: 8 bytes (src port, dst port, length, checksum)');
    console.log('  Checksum for error detection only - corrupt = discard and forget');

    section('TCP overhead');
    console.log('  Data overhead:       20-60 byte header vs UDP 8 bytes');
    console.log('  Processing overhead: connection state, ACK tracking, retransmit logic');
    console.log('  Time overhead:       three-way handshake latency before first byte');

    section('When TCP is preferred');
    const tcpServices = PORT_TABLE.filter((r: any) => r.transport === 'TCP' || r.transport === 'TCP/UDP');
    const examples = tcpServices.slice(0, 4).map((r: any) => `${r.name}/${r.port}`).join(', ');
    console.log(`  File transfer, web browsing, email - e.g. ${examples}`);
    console.log('  Data integrity > speed; minor latency from retransmit is acceptable.');

    section('When UDP is preferred');
    const udpServices = PORT_TABLE.filter((r: any) => r.transport === 'UDP');
    const udpEx = udpServices.slice(0, 3).map((r: any) => `${r.name}/${r.port}`).join(', ');
    console.log(`  Real-time: VoIP, video streaming, gaming - e.g. ${udpEx}`);
    console.log('  Simple query/response: DNS (small request, single response)');
    console.log('  App-layer reliability: TFTP ACKs every message itself -> uses UDP');
    console.log('  Lost data quickly becomes irrelevant; retransmit delay is worse.');

    await pressEnter(rl);
  } else if (topic === 'ports') {
    banner('Port Numbers & IANA Ranges');
    section('What is a port?');
    console.log('A 16-bit number (0-65535) addressing a message to a specific');
    console.log('application process on the destination host.');
    console.log('Source Port field = 16 bits -> 2^16 = 65,536 possible ports.');

    section('Session multiplexing');
    console.log('Client selects a random ephemeral port as SOURCE for each session.');
    console.log('Five-tuple (src-IP, src-port, dst-IP, dst-port, L4-proto) uniquely');
    console.log('identifies each session - how Chrome and Firefox stay separate.');

    section('IANA Port Tiers');
    for (const t of IANA_TIERS) {
      console.log(`  ${String(t.start).padEnd(6)}–${String(t.stop).padEnd(6)}  ${t.label}`);
      console.log(`         also called: ${t.alias}`);
    }

    section('Common protocols');
    console.log(`  ${'Protocol'.padEnd(10)} ${'Transport'.padEnd(9)} ${'Port'.padEnd(6)} IANA tier`);
    rule();
    for (const row of PORT_TABLE) {
      const tier = context.protocols.getPortType(row.port);
      console.log(`  ${row.name.padEnd(10)} ${row.transport.padEnd(9)} ${String(row.port).padEnd(6)} ${tier}`);
    }
    await pressEnter(rl);
  } else if (topic === 'standard') {
    banner('Standard ACLs');
    section('ACL fundamentals');
    console.log('An ordered list of ACEs (Access Control Entries) that filters packets');
    console.log('on a router interface. Logic: if-then-else, top-to-bottom.');
    console.log('  First matching ACE wins -> action taken, rest skipped.');
    console.log(`  Permit = forward.  Deny = discard.`);

    section('Standard ACL - what it matches');
    console.log('  Source IP address ONLY.');

    section('Implicit deny');
    console.log('  Hidden final rule: deny any.');
    console.log('  Every ACL ends with this; it never appears in "show access-lists".');
    console.log(`  If no ACE matches -> packet is Deny silently.`);
    console.log('  Add explicit "permit any" to allow unmatched traffic through.');

    section('Wildcard mask arithmetic');
    console.log("  Bit=0 -> MUST match.   Bit=1 -> ignore (don't care).");
    console.log('  Shortcut: subtract each subnet octet from 255.');
    for (const p of [24, 16, 28]) {
      console.log(`  /${p} -> wildcard ${prefixToWildcard(p)}`);
    }

    await pressEnter(rl);
  } else if (topic === 'extended') {
    banner('Extended ACLs');
    section('What extended ACLs can match');
    console.log('  Protocol payload: tcp | udp | icmp | ospf | ip (matches ALL IPv4)');
    console.log('  Source IP + wildcard   (or host <ip> or any)');
    console.log('  Source TCP/UDP port    (optional)');
    console.log('  Destination IP + wildcard');
    console.log('  Destination TCP/UDP port (optional)');
    console.log('  ALL specified parameters must match - no partial match counts.');

    section('Port operators');
    const ops: [string, string][] = [
      ['eq <port>', 'equal to port'],
      ['gt <port>', 'greater than port (exclusive)'],
      ['lt <port>', 'less than port (exclusive)'],
      ['neq <port>', 'not equal to port'],
      ['range <a> <b>', 'a to b inclusive'],
    ];
    for (const [op, meaning] of ops) console.log(`  ${op.padEnd(20)} -> ${meaning}`);

    await pressEnter(rl);
  } else if (topic === 'placement') {
    banner('Where to Apply ACLs');
    section('Direction');
    console.log('  INBOUND  (ingress): filters packets AS THEY ENTER the interface.');
    console.log('  OUTBOUND (egress):  filters packets AS THEY LEAVE the interface.');
    console.log('  Limit: max 1 inbound + 1 outbound ACL per interface.');
    console.log('  Same ACL may be applied to multiple interfaces.');

    section('Standard ACL placement - close to DESTINATION');
    console.log('  Standard ACLs filter only by source IP.');
    console.log('  Placing near source risks blocking that source from ALL destinations,');
    console.log('  not just the one you want to protect.');
    console.log('  -> Apply OUTBOUND on the interface connected to the protected LAN.');

    section('Extended ACL placement - close to SOURCE');
    console.log('  Extended ACLs precisely specify which traffic is blocked.');
    console.log('  Placing near source drops packets before they waste bandwidth');
    console.log('  traversing the network only to be denied at the last hop.');
    console.log('  -> Apply INBOUND on the interface closest to the originating host.');

    await pressEnter(rl);
  }
}
