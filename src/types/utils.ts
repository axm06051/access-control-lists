import { Ansi, Operation, PAD, ReservedRanges } from './constants';
import type { AclKind, AclRange, BitIndex, OctetIndex, PortOperator } from './constants';
import { IPv4 } from './protocols';

type FirstConflict = readonly [octetIndex: number, bitIndex: number] | undefined;

export function operationName(op: Operation): string {
  return Operation[op];
}

export function inferKindFromNumber(id: number): AclKind {
  const inRange = (n: number, { start, stop }: AclRange): boolean => ((n - start) | (stop - n)) >= 0;

  for (const [kind, ranges] of Object.entries(ReservedRanges)) {
    if (ranges.some((r) => inRange(id, r))) return kind as AclKind;
  }
  throw new RangeError(
    `ACL number ${id} is not in a reserved range. ` + `Standard: 1–99, 1300–1999. Extended: 100–199, 2000–2699.`
  );
}

export type PortCondition =
  | { op: Exclude<PortOperator, 'range'>; port: number }
  | { op: 'range'; portA: number; portB: number };

export class PortMatcher {
  readonly condition: PortCondition;

  constructor(condition: PortCondition) {
    this.condition = condition;
  }

  matches(port: number): boolean {
    const c = this.condition;
    switch (c.op) {
      case 'eq':
        return port === c.port;
      case 'gt':
        return port > c.port;
      case 'lt':
        return port < c.port;
      case 'neq':
        return port !== c.port;
      case 'range':
        return port >= c.portA && port <= c.portB;
    }
  }

  toString(): string {
    const c = this.condition;
    return c.op === 'range' ? `range ${c.portA} ${c.portB}` : `${c.op} ${c.port}`;
  }
}

export class AceMatch {
  readonly isMatch: boolean;
  readonly exitAt: FirstConflict;
  readonly src: IPv4;
  readonly target: IPv4;
  readonly wildcard: IPv4;

  constructor(isMatch: boolean, src: IPv4, target: IPv4, wildcard: IPv4, exitAt?: FirstConflict) {
    this.isMatch = isMatch;
    this.src = src;
    this.target = target;
    this.wildcard = wildcard;
    this.exitAt = exitAt;
  }
}

export class WildcardMatcher {
  readonly target: IPv4;
  readonly wildcard: IPv4;

  constructor(ip: string, wildcard: string) {
    this.target = new IPv4(ip);
    this.wildcard = new IPv4(wildcard);
  }

  match(srcIpAddress: string): AceMatch {
    const lastOctet: OctetIndex = 3;
    const firstOctet: OctetIndex = 0;
    const MSb: BitIndex = 7;
    const LSb: BitIndex = 0;
    const src = new IPv4(srcIpAddress);

    for (let o = lastOctet; o >= firstOctet; o--) {
      const oi = o as OctetIndex;
      const srcOctet = src.binary[oi];
      const tgtOctet = this.target.binary[oi];
      const wcOctet = this.wildcard.binary[oi];

      for (let i = MSb; i >= LSb; i--) {
        const bi = i as BitIndex;
        const mustMatch = wcOctet[bi] === '0';
        const isMatch = srcOctet[bi] === tgtOctet[bi];
        if (mustMatch && !isMatch) {
          return new AceMatch(false, src, this.target, this.wildcard, [oi, bi]);
        }
      }
    }
    return new AceMatch(true, src, this.target, this.wildcard);
  }

  showMiss(match: AceMatch): void {
    const [octetIdx, bitIdx] = match.exitAt ?? [0 as OctetIndex, 0 as BitIndex];

    const LABEL_WIDTH = 8;
    const DEC_WIDTH = PAD.ipv4;
    const POINTER_OFFSET = LABEL_WIDTH + 3 + DEC_WIDTH + 2;

    const row = (label: string, ip: IPv4): string => {
      const dec = ip.toString().padEnd(DEC_WIDTH);
      const bin = ip.binary
        .map((oct, i): string => {
          if (i !== octetIdx) return oct;
          const char = oct[bitIdx] ?? '?';
          return oct.slice(0, bitIdx) + Ansi.red(char) + oct.slice(bitIdx + 1);
        })
        .join('.');
      return `${label.padEnd(LABEL_WIDTH)} : ${dec}  ${bin}`;
    };

    const pointerLine =
      ' '.repeat(POINTER_OFFSET) +
      match.target.binary
        .map((oct, i) =>
          i === octetIdx ? `${' '.repeat(bitIdx)}^${' '.repeat(oct.length - bitIdx - 1)}` : `${' '.repeat(oct.length)}`
        )
        .join('.');

    console.log(
      ['', row('src', match.src), row('target', match.target), pointerLine, row('wild', match.wildcard), ''].join('\n')
    );
  }
}
