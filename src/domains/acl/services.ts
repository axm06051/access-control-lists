import { AclKind, AclIdType, Operation, Packet, L3Protocol, PortCondition } from './types';
import { AccessControlEntry, StandardACE, ExtendedACE, StandardACEParams, ExtendedACEParams } from './entities';
import { operationName } from '../shared/utils';

export type AclId = number | string;

export interface AclEntry {
  id: AclId;
  rules: AccessControlEntry[];
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
    return this.#registry.delete(this.#key(aclId));
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
    return this.#registry.has(this.#key(aclId));
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
