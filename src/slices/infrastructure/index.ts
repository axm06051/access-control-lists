import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';
import type { Packet, L3Protocol } from '@/domains/acl/types';

export { AccessList } from '@/domains/acl/services';
export { ExtendedACE, type ExtendedACEParams } from '@/domains/acl/entities';
export { Operation } from '@/domains/acl/constants';
export type { Packet, L3Protocol } from '@/domains/acl/types';

export const INFRASTRUCTURE_PORTS = {
  DNS: 53,
  DHCP_SERVER: 67,
  DHCP_CLIENT: 68,
  ICMP: 0,
  OSPF: 89,
  SSH: 22,
  TELNET: 23,
} as const;

export const INFRASTRUCTURE_PROTOCOLS = {
  DNS: 'udp',
  DHCP: 'udp',
  ICMP: 'icmp',
  OSPF: 'ip',
  SSH: 'tcp',
  TELNET: 'tcp',
} as const;

export class InfrastructureFilteringService {
  private acl: AccessList;

  constructor() {
    this.acl = new AccessList();
  }

  permitDnsTraffic(aclId: string | number): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'udp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: INFRASTRUCTURE_PORTS.DNS },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: INFRASTRUCTURE_PORTS.DNS },
    });
  }

  permitDhcpTraffic(aclId: string | number): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'udp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: INFRASTRUCTURE_PORTS.DHCP_SERVER },
    });
  }

  permitIcmpTraffic(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'icmp',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
    });
  }

  permitOspfTraffic(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'ospf',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
    });
  }

  permitSshTelnet(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: INFRASTRUCTURE_PORTS.SSH },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: INFRASTRUCTURE_PORTS.TELNET },
    });
  }

  getAccessList(): AccessList {
    return this.acl;
  }
}
