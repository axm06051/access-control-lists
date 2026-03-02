import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';
import type { Packet, L3Protocol } from '@/domains/acl/types';

export { AccessList } from '@/domains/acl/services';
export { StandardACE, ExtendedACE, type StandardACEParams, type ExtendedACEParams } from '@/domains/acl/entities';
export { Operation } from '@/domains/acl/constants';
export type { Packet, L3Protocol } from '@/domains/acl/types';

export const MANAGEMENT_PORTS = {
  SSH: 22,
  TELNET: 23,
  SNMP: 161,
  SNMP_TRAP: 162,
} as const;

export const MANAGEMENT_PROTOCOLS = {
  SSH: 'tcp',
  TELNET: 'tcp',
  SNMP: 'udp',
} as const;

export class ManagementAccessService {
  private acl: AccessList;

  constructor() {
    this.acl = new AccessList();
  }

  restrictSshToNetwork(aclId: string | number, adminNetwork: string, adminWildcard: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: adminNetwork,
      srcWildcard: adminWildcard,
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.SSH },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Deny,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.SSH },
    });
  }

  restrictTelnetToNetwork(aclId: string | number, adminNetwork: string, adminWildcard: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: adminNetwork,
      srcWildcard: adminWildcard,
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.TELNET },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Deny,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.TELNET },
    });
  }

  restrictSnmpToNetwork(aclId: string | number, monitoringNetwork: string, monitoringWildcard: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'udp',
      srcIp: monitoringNetwork,
      srcWildcard: monitoringWildcard,
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.SNMP },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'udp',
      srcIp: monitoringNetwork,
      srcWildcard: monitoringWildcard,
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.SNMP_TRAP },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Deny,
      protocol: 'udp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: MANAGEMENT_PORTS.SNMP },
    });
  }

  getAccessList(): AccessList {
    return this.acl;
  }
}
