import { IPv4 } from './value-objects';
import type { PortCondition, OctetIndex, BitIndex } from '../acl/types';

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
  readonly exitAt: readonly [OctetIndex, BitIndex] | undefined;
  readonly src: IPv4;
  readonly target: IPv4;
  readonly wildcard: IPv4;

  constructor(isMatch: boolean, src: IPv4, target: IPv4, wildcard: IPv4, exitAt?: readonly [OctetIndex, BitIndex]) {
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
    const src = new IPv4(srcIpAddress);

    for (let o = 3; o >= 0; o--) {
      const oi = o as OctetIndex;
      const srcOctet = src.binary[oi];
      const tgtOctet = this.target.binary[oi];
      const wcOctet = this.wildcard.binary[oi];

      for (let i = 7; i >= 0; i--) {
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
}
