import { AclKind, Operation, Packet, L3Protocol, PortCondition } from './types';
import { IPv4 } from '../shared/value-objects';
import { PortMatcher, WildcardMatcher } from '../shared/services';
import { operationName } from '../shared/utils';
import { PAD } from './constants';

export type StandardACEParams = {
  op: Operation;
  srcIp: string;
  wildcardMask: string;
};

export type ExtendedACEParams = {
  op: Operation;
  protocol: L3Protocol;
  srcIp: string;
  srcWildcard: string;
  dstIp: string;
  dstWildcard: string;
  srcPort?: PortCondition;
  dstPort?: PortCondition;
};

export abstract class AccessControlEntry {
  #seq: number;
  readonly #op: Operation;

  constructor(sequenceNumber: number, operation: Operation) {
    this.#seq = sequenceNumber;
    this.#op = operation;
  }

  get sequenceNumber(): number {
    return this.#seq;
  }

  get operation(): Operation {
    return this.#op;
  }

  abstract get kind(): AclKind;
  abstract assess(packet: Packet): boolean;
  abstract toString(): string;

  resequence(n: number): void {
    this.#seq = n;
  }

  resolveAction(isMatch: boolean): Operation {
    return isMatch ? this.#op : Operation.Deny;
  }
}

export class StandardACE extends AccessControlEntry {
  readonly #matcher: WildcardMatcher;

  get kind(): AclKind {
    return AclKind.Standard;
  }

  constructor(seq: number, params: StandardACEParams) {
    super(seq, params.op);
    this.#matcher = new WildcardMatcher(params.srcIp, params.wildcardMask);
  }

  assess(packet: Packet): boolean {
    return this.#matcher.match(packet.srcIp).isMatch;
  }

  toString(): string {
    const seq = this.sequenceNumber.toString().padEnd(PAD.index);
    const op = operationName(this.operation).padEnd(PAD.operation);
    const src = this.#matcher.target.toString().padEnd(PAD.ipv4);
    const wc = this.#matcher.wildcard.toString().padEnd(PAD.wildcard);
    return `${seq} ${op} ${src} ${wc}`;
  }
}

export class ExtendedACE extends AccessControlEntry {
  readonly #protocol: L3Protocol;
  readonly #srcMatcher: WildcardMatcher;
  readonly #dstMatcher: WildcardMatcher;
  readonly #srcPort: PortMatcher | undefined;
  readonly #dstPort: PortMatcher | undefined;

  get kind(): AclKind {
    return AclKind.Extended;
  }

  constructor(seq: number, params: ExtendedACEParams) {
    super(seq, params.op);
    this.#protocol = params.protocol;
    this.#srcMatcher = new WildcardMatcher(params.srcIp, params.srcWildcard);
    this.#dstMatcher = new WildcardMatcher(params.dstIp, params.dstWildcard);
    this.#srcPort = params.srcPort ? new PortMatcher(params.srcPort) : undefined;
    this.#dstPort = params.dstPort ? new PortMatcher(params.dstPort) : undefined;
  }

  assess(packet: Packet): boolean {
    if (this.#protocol !== 'ip' && this.#protocol !== packet.protocol) return false;
    if (!this.#srcMatcher.match(packet.srcIp).isMatch) return false;
    if (!this.#dstMatcher.match(packet.dstIp).isMatch) return false;
    if (this.#srcPort && (packet.srcPort === undefined || !this.#srcPort.matches(packet.srcPort))) return false;
    if (this.#dstPort && (packet.dstPort === undefined || !this.#dstPort.matches(packet.dstPort))) return false;
    return true;
  }

  toString(): string {
    const seq = this.sequenceNumber.toString().padEnd(PAD.index);
    const op = operationName(this.operation).padEnd(PAD.operation);
    const proto = this.#protocol.padEnd(PAD.protocol);
    const src = this.#srcMatcher.target.toString().padEnd(PAD.ipv4);
    const srcWc = this.#srcMatcher.wildcard.toString().padEnd(PAD.wildcard);
    const sp = (this.#srcPort?.toString() ?? '').padEnd(PAD.portCond);
    const dst = this.#dstMatcher.target.toString().padEnd(PAD.ipv4);
    const dstWc = this.#dstMatcher.wildcard.toString().padEnd(PAD.wildcard);
    const dp = this.#dstPort?.toString() ?? '';

    const portSection = this.#srcPort || this.#dstPort ? `  ${sp}  ${dst} ${dstWc}  ${dp}` : `  ${dst} ${dstWc}`;

    return `${seq} ${op} ${proto} ${src} ${srcWc}${portSection}`;
  }
}
