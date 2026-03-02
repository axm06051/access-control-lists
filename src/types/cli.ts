import * as readline from 'readline';
import { AccessList, type AclId } from './acls';
import { AclKind } from './constants';
import { Ansi, Operation } from './constants';
import type { L3Protocol, Packet } from './protocols';
import { type PortCondition, inferKindFromNumber } from './utils';
import { protocols } from './protocols';

type Mode = 'user-exec' | 'priv-exec' | 'global-config' | 'std-nacl' | 'ext-nacl';
interface NamedNaclContext {
  id: AclId;
  kind: AclKind;
}

class CiscoAclCli {
  readonly #hostname: string;
  #mode: Mode = 'user-exec';
  #naclCtx: NamedNaclContext | null = null;
  readonly #acl = new AccessList();

  constructor(hostname = 'Router') {
    this.#hostname = hostname;
  }

  dispatch(line: string): boolean {
    const args = this.#tokens(line);
    if (!args.length) return true;

    switch (this.#mode) {
      case 'user-exec':
        return this.#handleUserExec(args);
      case 'priv-exec':
        return this.#handlePrivExec(args);
      case 'global-config':
        return this.#handleGlobalConfig(args);
      case 'std-nacl':
      case 'ext-nacl':
        return this.#handleNaclMode(args);
    }
  }

  get prompt(): string {
    switch (this.#mode) {
      case 'user-exec':
        return `${this.#hostname}> `;
      case 'priv-exec':
        return `${this.#hostname}# `;
      case 'global-config':
        return `${this.#hostname}(config)# `;
      case 'std-nacl':
        return `${this.#hostname}(config-std-nacl)# `;
      case 'ext-nacl':
        return `${this.#hostname}(config-ext-nacl)# `;
    }
  }

  #handleUserExec(args: string[]): boolean {
    const [cmd] = args;
    if (cmd === 'enable') {
      this.#mode = 'priv-exec';
      return true;
    }
    if (cmd === 'exit' || cmd === 'quit') return false;
    if (cmd === '?' || cmd === 'help') {
      this.#printHelp();
      return true;
    }
    console.log(`% Unknown command: ${args.join(' ')}`);
    return true;
  }

  #handlePrivExec(args: string[]): boolean {
    const cmd = args[0];
    if (cmd === 'configure' || cmd === 'conf') {
      this.#mode = 'global-config';
      return true;
    }
    if (cmd === 'show') {
      if (args[1] === 'access-lists' || args[1] === 'ip') {
        this.#showAcls(args[2]);
        return true;
      }
    }
    if (cmd === 'validate') {
      this.#handleValidate(args.slice(1));
      return true;
    }
    if (cmd === 'disable') {
      this.#mode = 'user-exec';
      return true;
    }
    if (cmd === 'exit' || cmd === 'end' || cmd === 'quit') return false;
    if (cmd === '?' || cmd === 'help') {
      this.#printHelp();
      return true;
    }
    console.log(`% Unknown command: ${args.join(' ')}`);
    return true;
  }

  #handleGlobalConfig(args: string[]): boolean {
    const [cmd, ...rest] = args;
    if (!cmd) return true;

    if (cmd === 'do') {
      this.#handlePrivExec(rest);
      return true;
    }

    if (cmd === 'access-list') {
      this.#handleAccessList(rest);
      return true;
    }

    if (cmd === 'ip' && rest[0] === 'access-list') {
      const kindStr = rest[1];
      const nameOrNum = rest[2];

      if (kindStr === 'resequence') {
        this.#handleResequence(rest.slice(2));
        return true;
      }

      if (!nameOrNum) {
        console.log('% Missing ACL name or number');
        return true;
      }

      if (kindStr === 'standard') {
        const id: AclId = isNaN(Number(nameOrNum)) ? nameOrNum : Number(nameOrNum);
        this.#naclCtx = { id, kind: AclKind.Standard };
        this.#mode = 'std-nacl';
      } else if (kindStr === 'extended') {
        const id: AclId = isNaN(Number(nameOrNum)) ? nameOrNum : Number(nameOrNum);
        this.#naclCtx = { id, kind: AclKind.Extended };
        this.#mode = 'ext-nacl';
      } else {
        console.log('% Usage: ip access-list {standard|extended} <name|number>');
      }
      return true;
    }

    if (cmd === 'no' && rest[0] === 'access-list') {
      const rawNo = rest[1];
      if (!rawNo) {
        console.log('% Invalid ACL number');
        return true;
      }
      const id = parseInt(rawNo, 10);
      if (isNaN(id)) {
        console.log('% Invalid ACL number');
        return true;
      }
      const deleted = this.#acl.deleteAcl(id);
      console.log(deleted ? '' : `% ACL ${id} not found`);
      return true;
    }

    if (cmd === 'end' || cmd === 'exit') {
      this.#mode = 'priv-exec';
      return true;
    }
    if (cmd === '?' || cmd === 'help') {
      this.#printHelp();
      return true;
    }
    console.log(`% Unknown command: ${args.join(' ')}`);
    return true;
  }

  #handleNaclMode(args: string[]): boolean {
    const [cmd] = args;
    if (cmd === 'exit') {
      this.#mode = 'global-config';
      this.#naclCtx = null;
      return true;
    }
    if (cmd === 'end') {
      this.#mode = 'priv-exec';
      this.#naclCtx = null;
      return true;
    }
    if (cmd === 'do') {
      this.#handlePrivExec(args.slice(1));
      return true;
    }
    if (cmd === '?' || cmd === 'help') {
      this.#printHelp();
      return true;
    }
    this.#handleNamedAclConfig(args);
    return true;
  }

  #handleAccessList(args: string[]): void {
    const rawId = args[0];
    if (!rawId) {
      console.log('% Invalid ACL number');
      return;
    }
    const id = parseInt(rawId, 10);
    if (isNaN(id)) {
      console.log('% Invalid ACL number');
      return;
    }

    const op = this.#parseOperation(args[1]);
    if (op === null) {
      console.log('% Expected permit or deny');
      return;
    }

    let kind: AclKind;
    try {
      kind = inferKindFromNumber(id);
    } catch (e: unknown) {
      console.log(`% ${(e as Error).message}`);
      return;
    }

    const rest = args.slice(2);

    if (kind === 'Standard') {
      const iw = this.#parseIpWildcard(rest, 0);
      if (!iw) {
        console.log('% Invalid source address');
        return;
      }
      this.#acl.addStandard(id, {
        op,
        srcIp: iw.ip,
        wildcardMask: iw.wc,
      });

      console.log('');
    } else {
      const protoRaw = rest[0];
      if (!protoRaw || !['ip', 'tcp', 'udp', 'icmp', 'ospf'].includes(protoRaw)) {
        console.log('% Unknown protocol. Use: ip tcp udp icmp ospf');
        return;
      }
      const proto = protoRaw as L3Protocol;
      let idx = 1;

      const src = this.#parseIpWildcard(rest, idx);
      if (!src) {
        console.log('% Invalid source address');
        return;
      }
      idx += src.consumed;

      const sp = this.#parsePortCondition(rest, idx);
      if (sp) idx += sp.consumed;

      const dst = this.#parseIpWildcard(rest, idx);
      if (!dst) {
        console.log('% Invalid destination address');
        return;
      }
      idx += dst.consumed;

      const dp = this.#parsePortCondition(rest, idx);
      this.#acl.addExtended(id, {
        op,
        protocol: proto,
        srcIp: src.ip,
        srcWildcard: src.wc,
        dstIp: dst.ip,
        dstWildcard: dst.wc,
        ...(sp?.cond && { srcPort: sp.cond }),
        ...(dp?.cond && { dstPort: dp.cond }),
      });
      console.log('');
    }
  }

  #handleNamedAclConfig(args: string[]): void {
    if (!this.#naclCtx) return;
    const { id, kind } = this.#naclCtx;
    const first = args[0];
    if (!first) return;

    if (first === 'no') {
      const rawSeq = args[1];
      if (!rawSeq) {
        console.log('% Usage: no <sequence-number>');
        return;
      }
      const seq = parseInt(rawSeq, 10);
      if (isNaN(seq)) {
        console.log('% Usage: no <sequence-number>');
        return;
      }
      const ok = this.#acl.deleteAce(id, seq);
      console.log(ok ? '' : `% Sequence ${seq} not found in ACL '${id}'`);
      return;
    }

    let idx = 0;
    let seq: number | undefined;
    if (!isNaN(parseInt(first, 10)) && first !== 'permit' && first !== 'deny') {
      seq = parseInt(first, 10);
      idx = 1;
    }

    const op = this.#parseOperation(args[idx]);
    if (op === null) {
      console.log('% Expected permit or deny');
      return;
    }
    idx++;

    if (kind === 'Standard') {
      const iw = this.#parseIpWildcard(args, idx);
      if (!iw) {
        console.log('% Invalid source address');
        return;
      }
      void seq;
      this.#acl.addStandard(String(id), {
        op,
        srcIp: iw.ip,
        wildcardMask: iw.wc,
      });
      console.log('');
    } else {
      const protoRaw = args[idx];
      if (!protoRaw || !['ip', 'tcp', 'udp', 'icmp', 'ospf'].includes(protoRaw)) {
        console.log('% Unknown protocol. Use: ip tcp udp icmp ospf');
        return;
      }
      const proto = protoRaw as L3Protocol;
      idx++;

      const src = this.#parseIpWildcard(args, idx);
      if (!src) {
        console.log('% Invalid source address');
        return;
      }
      idx += src.consumed;

      const sp = this.#parsePortCondition(args, idx);
      if (sp) idx += sp.consumed;

      const dst = this.#parseIpWildcard(args, idx);
      if (!dst) {
        console.log('% Invalid destination address');
        return;
      }
      idx += dst.consumed;

      const dp = this.#parsePortCondition(args, idx);
      void seq;
      this.#acl.addExtended(String(id), {
        op,
        protocol: proto,
        srcIp: src.ip,
        srcWildcard: src.wc,
        dstIp: dst.ip,
        dstWildcard: dst.wc,
        ...(sp?.cond && { srcPort: sp.cond }),
        ...(dp?.cond && { dstPort: dp.cond }),
      });
      console.log('');
    }
  }

  #handleValidate(args: string[]): void {
    if (args.length < 2) {
      console.log('% Usage: validate <acl-id|name> <srcIp> [dstIp] [protocol] [srcPort] [dstPort]');
      return;
    }

    const rawId = args[0];
    if (!rawId) {
      console.log('% Missing ACL id or name');
      return;
    }
    const aclId: AclId = isNaN(Number(rawId)) ? rawId : Number(rawId);

    const srcIp = args[1];
    if (!srcIp) {
      console.log('% Missing source IP');
      return;
    }

    const dstIp = args[2] ?? '0.0.0.0';
    const proto = (args[3] ?? 'ip') as L3Protocol;
    const srcPort = args[4] ? (this.#resolvePort(args[4]) ?? undefined) : undefined;
    const dstPort = args[5] ? (this.#resolvePort(args[5]) ?? undefined) : undefined;

    const packet: Packet = {
      protocol: proto,
      srcIp,
      dstIp,
      ...(srcPort !== undefined && { srcPort }),
      ...(dstPort !== undefined && { dstPort }),
    };

    const result = this.#acl.validate(packet, aclId);
    const colour = result === 'Permit' ? Ansi.green : Ansi.red;
    console.log(
      colour(
        `\n  ${srcIp} → ${dstIp}  [${proto}` +
          `${srcPort !== undefined ? ` src:${srcPort}` : ''}` +
          `${dstPort !== undefined ? ` dst:${dstPort}` : ''}` +
          `]  ACL '${aclId}' → ${Ansi.bold(result)}\n`
      )
    );
  }

  #handleResequence(args: string[]): void {
    const [rawId, rawStart, rawIncr] = args;
    if (!rawId || !rawStart || !rawIncr) {
      console.log('% Usage: ip access-list resequence <id|name> <start> <increment>');
      return;
    }
    const start = parseInt(rawStart, 10);
    const incr = parseInt(rawIncr, 10);
    if (isNaN(start) || isNaN(incr)) {
      console.log('% Usage: ip access-list resequence <id|name> <start> <increment>');
      return;
    }
    const id: AclId = isNaN(Number(rawId)) ? rawId : Number(rawId);
    try {
      this.#acl.resequence(id, start, incr);
      console.log('');
    } catch (e: unknown) {
      console.log(`% ${(e as Error).message}`);
    }
  }

  #showAcls(specificId?: string): void {
    if (specificId) {
      const id = isNaN(Number(specificId)) ? specificId : Number(specificId);
      console.log(this.#acl.showAcl(id));
    } else {
      const out = this.#acl.toString();
      console.log(out || '% No access lists configured');
    }
  }

  #tokens(line: string): string[] {
    return line.trim().split(/\s+/).filter(Boolean);
  }

  #parseOperation(s: string | undefined): Operation | null {
    if (s === 'permit') return Operation.Permit;
    if (s === 'deny') return Operation.Deny;
    return null;
  }

  #parseIpWildcard(args: string[], idx: number): { ip: string; wc: string; consumed: number } | null {
    if (args[idx] === 'any') return { ip: '0.0.0.0', wc: '255.255.255.255', consumed: 1 };
    if (args[idx] === 'host') {
      const hostIp = args[idx + 1];
      if (!hostIp) return null;
      return { ip: hostIp, wc: '0.0.0.0', consumed: 2 };
    }
    const ip = args[idx];
    const wc = args[idx + 1];
    return ip && wc ? { ip, wc, consumed: 2 } : null;
  }

  #resolvePort(s: string): number | null {
    return protocols.tcp.resolvePort(s) ?? protocols.udp.resolvePort(s);
  }

  #parsePortCondition(args: string[], idx: number): { cond: PortCondition; consumed: number } | null {
    const op = args[idx];
    if (!op || !['eq', 'gt', 'lt', 'neq', 'range'].includes(op)) return null;
    const typedOp = op as 'eq' | 'gt' | 'lt' | 'neq' | 'range';

    if (typedOp === 'range') {
      const p1 = this.#resolvePort(args[idx + 1] ?? '');
      const p2 = this.#resolvePort(args[idx + 2] ?? '');
      if (p1 === null || p2 === null) return null;
      return { cond: { op: 'range', portA: p1, portB: p2 }, consumed: 3 };
    }

    const p = this.#resolvePort(args[idx + 1] ?? '');
    if (p === null) return null;
    return { cond: { op: typedOp, port: p }, consumed: 2 };
  }

  #printHelp(): void {
    const h = Ansi.cyan;
    const b = Ansi.bold;

    switch (this.#mode) {
      case 'user-exec':
        console.log(h('\nUser Exec commands:'));
        console.log('  enable                       Enter privileged exec mode');
        console.log('  exit / quit                  Exit the program\n');
        break;

      case 'priv-exec':
        console.log(h('\nPrivileged Exec commands:'));
        console.log('  configure terminal (conf t)  Enter global config mode');
        console.log('  show access-lists [id|name]  Show all ACLs or a specific one');
        console.log('  show ip access-lists         Show IP ACLs');
        console.log('  validate <acl> <packet>      Test a packet against an ACL');
        console.log('  disable                      Return to user exec');
        console.log('  exit / end                   Exit\n');
        console.log(b('  validate syntax:'));
        console.log('  validate <acl-id|name> <srcIp> [dstIp] [proto] [srcPort] [dstPort]');
        console.log('  proto: ip tcp udp icmp ospf');
        console.log('  port:  number or keyword (www=80, https=443, ntp=123, tftp=69, etc.)\n');
        break;

      case 'global-config':
        console.log(h('\nGlobal Config commands:'));
        console.log(b('  Standard Numbered:'));
        console.log('  access-list <1-99|1300-1999> {permit|deny} <src> <wildcard>');
        console.log('  access-list <1-99|1300-1999> {permit|deny} host <ip>');
        console.log('  access-list <1-99|1300-1999> {permit|deny} any');
        console.log(b('\n  Extended Numbered:'));
        console.log('  access-list <100-199|2000-2699> {permit|deny} <proto> <src> <wc> [sp] <dst> <wc> [dp]');
        console.log(b('\n  Named ACL (Standard or Extended):'));
        console.log('  ip access-list standard <name|number>');
        console.log('  ip access-list extended <name|number>');
        console.log(b('\n  Other:'));
        console.log('  no access-list <id>          Delete a numbered ACL');
        console.log('  ip access-list resequence <id|name> <start> <increment>');
        console.log('  do show access-lists         Show ACLs from config mode');
        console.log('  do validate <acl> <packet>   Validate from config mode');
        console.log('  end / exit\n');
        break;

      case 'std-nacl':
      case 'ext-nacl': {
        const isExt = this.#mode === 'ext-nacl';
        console.log(h(`\n${isExt ? 'Extended' : 'Standard'} Named ACL Config commands:`));
        if (isExt) {
          console.log('  [seq] {permit|deny} <proto> <src> <wc> [srcPort] <dst> <wc> [dstPort]');
          console.log('  proto: ip  tcp  udp  icmp  ospf');
          console.log('  port : eq|gt|lt|neq <port>   or   range <start> <end>');
        } else {
          console.log('  [seq] {permit|deny} {any | host <ip> | <ip> <wildcard>}');
        }
        console.log('  no <seq>                     Delete ACE by sequence number');
        console.log('  exit                         Return to global config');
        console.log('  end                          Return to privileged exec\n');
        break;
      }
    }
  }
}

function printWelcome(): void {
  const title = 'Access Control List Practice';
  const padding = 2;
  const horizontal = '═';
  const vertical = '║';
  const topLeft = '╔';
  const topRight = '╗';
  const bottomLeft = '╚';
  const bottomRight = '╝';
  const contentWidth = title.length + padding * 4;
  const border = horizontal.repeat(contentWidth);
  const top = `${topLeft}${border}${topRight}`;
  const bottom = `${bottomLeft}${border}${bottomRight}`;
  const leftSpace = Math.floor((contentWidth - title.length) / 2);
  const rightSpace = contentWidth - title.length - leftSpace;
  const middle = vertical + ' '.repeat(leftSpace) + title + ' '.repeat(rightSpace) + vertical;
  console.log(Ansi.bold(Ansi.cyan([top, middle, bottom].join('\n'))));
}

export function main(): void {
  printWelcome();

  const cli = new CiscoAclCli('Router');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
    prompt: cli.prompt,
  });

  rl.prompt();

  rl.on('line', (line: string) => {
    const keepGoing = cli.dispatch(line.trim());

    if (!keepGoing) {
      console.log(Ansi.cyan('\nGoodbye!\n'));
      rl.close();
      process.exit(0);
    }

    rl.setPrompt(cli.prompt);
    rl.prompt();
  });

  rl.on('close', () => {
    console.log(Ansi.cyan('\nConnection closed.\n'));
    process.exit(0);
  });
}
