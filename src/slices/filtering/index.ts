import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';
import type { PortCondition, Packet } from '@/domains/acl/types';

export { AccessList, type AclEntry } from '@/domains/acl/services';
export { StandardACE, ExtendedACE, type StandardACEParams, type ExtendedACEParams } from '@/domains/acl/entities';
export { Operation, AclKind, AclIdType } from '@/domains/acl/constants';
export { PortMatcher, WildcardMatcher, AceMatch } from '@/domains/shared/services';
export { IPv4 } from '@/domains/shared/value-objects';
export type { Packet, L3Protocol, PortCondition, PortOperator } from '@/domains/acl/types';

export class FilteringService {
  private acl: AccessList;

  constructor() {
    this.acl = new AccessList();
  }

  addStandardRule(id: string | number, operation: Operation, srcIp: string, wildcardMask: string): void {
    this.acl.addStandard(id, { op: operation, srcIp, wildcardMask });
  }

  addExtendedRule(
    id: string | number,
    operation: Operation,
    protocol: string,
    srcIp: string,
    srcWildcard: string,
    dstIp: string,
    dstWildcard: string,
    srcPort?: PortCondition,
    dstPort?: PortCondition
  ): void {
    const params: any = {
      op: operation,
      protocol: protocol as any,
      srcIp,
      srcWildcard,
      dstIp,
      dstWildcard,
    };
    if (srcPort) params.srcPort = srcPort;
    if (dstPort) params.dstPort = dstPort;
    this.acl.addExtended(id, params);
  }

  evaluatePacket(packet: Packet, aclId: string | number): string {
    return this.acl.validate(packet, aclId);
  }

  deleteRule(aclId: string | number, sequenceNumber: number): boolean {
    return this.acl.deleteAce(aclId, sequenceNumber);
  }

  deleteAcl(aclId: string | number): boolean {
    return this.acl.deleteAcl(aclId);
  }

  resequenceAcl(aclId: string | number, start: number, increment: number): void {
    this.acl.resequence(aclId, start, increment);
  }

  displayAcl(aclId: string | number): string {
    return this.acl.showAcl(aclId);
  }

  hasAcl(aclId: string | number): boolean {
    return this.acl.hasAcl(aclId);
  }

  getAccessList(): AccessList {
    return this.acl;
  }
}
