import { AclIdType, AclKind, Operation, PAD } from './constants';
import type { L3Protocol, Packet } from './protocols';
import { operationName, PortMatcher, WildcardMatcher } from './utils';
import type { PortCondition } from './utils';

export type AclId = number | string;

type StandardACEParams = {
  op: Operation;
  srcIp: string;
  wildcardMask: string;
};

type ExtendedACEParams = {
  op: Operation;
  protocol: L3Protocol;
  srcIp: string;
  srcWildcard: string;
  dstIp: string;
  dstWildcard: string;
  srcPort?: PortCondition;
  dstPort?: PortCondition;
};

interface AclEntry {
  id: AclId;
  rules: AccessControlEntry[];
}
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
    if (isMatch) {
      console.log(this.#seq, operationName(this.#op));
      return this.#op;
    }
    return Operation.Deny;
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
    const match = this.#matcher.match(packet.srcIp);
    if (!match.isMatch) this.#matcher.showMiss(match);
    return match.isMatch;
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
    const { op, protocol, srcIp, srcWildcard, dstIp, dstWildcard, srcPort, dstPort } = params;
    super(seq, op);

    this.#protocol = protocol;
    this.#srcMatcher = new WildcardMatcher(srcIp, srcWildcard);
    this.#dstMatcher = new WildcardMatcher(dstIp, dstWildcard);
    this.#srcPort = srcPort ? new PortMatcher(srcPort) : undefined;
    this.#dstPort = dstPort ? new PortMatcher(dstPort) : undefined;
  }

  assess(packet: Packet): boolean {
    if (this.#protocol !== 'ip' && this.#protocol !== packet.protocol) return false;

    const srcMatch = this.#srcMatcher.match(packet.srcIp);
    if (!srcMatch.isMatch) {
      this.#srcMatcher.showMiss(srcMatch);
      return false;
    }

    const dstMatch = this.#dstMatcher.match(packet.dstIp);
    if (!dstMatch.isMatch) {
      this.#dstMatcher.showMiss(dstMatch);
      return false;
    }

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

export class AccessList {
  #incrementBy = 10;
  readonly #registry = new Map<string, AclEntry>();

  setIncrement(n: number): void {
    this.#incrementBy = n;
  }

  addStandard(id: AclId, params: StandardACEParams): void {
    this.#addAce(id, new StandardACE(this.#nextSeq(id), params));
  }

  addExtended(id: AclId, params: ExtendedACEParams): void {
    this.#addAce(id, new ExtendedACE(this.#nextSeq(id), params));
  }

  deleteAce(aclId: AclId, seq: number): boolean {
    const entry = this.#get(aclId);
    if (!entry) return false;
    const before = entry.rules.length;
    entry.rules = entry.rules.filter((a) => a.sequenceNumber !== seq);
    return entry.rules.length < before;
  }

  deleteAcl(aclId: AclId): boolean {
    return this.#registry.delete(String(aclId));
  }

  resequence(aclId: AclId, start: number, increment: number): void {
    const entry = this.#get(aclId);
    if (!entry) throw new RangeError(`ACL '${aclId}' not found`);
    entry.rules.forEach((ace, i) => ace.resequence(start + i * increment));
  }

  validate(packet: Packet, aclId: AclId): string {
    const entry = this.#get(aclId);
    if (!entry) return operationName(Operation.Deny);
    for (const ace of entry.rules) {
      if (ace.assess(packet)) return operationName(ace.resolveAction(true));
    }
    return operationName(Operation.Deny);
  }

  showAcl(aclId: AclId): string {
    const entry = this.#get(aclId);
    return entry ? this.#renderEntry(entry) : `% ACL '${aclId}' not found\n`;
  }

  toString(listMarker = ' '): string {
    return [...this.#registry.values()].map((entry) => this.#renderEntry(entry, listMarker)).join('');
  }

  entries(): IterableIterator<AclEntry> {
    return this.#registry.values();
  }

  hasAcl(aclId: AclId): boolean {
    return this.#registry.has(String(aclId));
  }

  #key(id: AclId): string {
    return String(id);
  }

  #get(id: AclId): AclEntry | undefined {
    return this.#registry.get(this.#key(id));
  }

  #addAce(id: AclId, ace: AccessControlEntry): void {
    const key = this.#key(id);
    const entry = this.#registry.get(key) ?? { id, rules: [] };
    entry.rules.push(ace);
    this.#registry.set(key, entry);
  }

  #nextSeq(id: AclId): number {
    return (this.#get(id)?.rules.at(-1)?.sequenceNumber ?? 0) + this.#incrementBy;
  }

  #idType(id: AclId): AclIdType {
    return typeof id === 'number' ? AclIdType.Numbered : AclIdType.Named;
  }

  #renderEntry(entry: AclEntry, marker = ' '): string {
    const kind = entry.rules[0]?.kind;
    const listLabel = this.#idType(entry.id) === AclIdType.Numbered ? 'Access List' : 'access list';
    const label = `${kind} IP ${listLabel} ${entry.id}`;
    return [label, ...entry.rules.map((ace) => `${marker}${ace.toString()}`)].join('\n') + '\n';
  }
}
