import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';
import type { Packet, L3Protocol } from '@/domains/acl/types';

export { AccessList } from '@/domains/acl/services';
export { ExtendedACE, type ExtendedACEParams } from '@/domains/acl/entities';
export { Operation } from '@/domains/acl/constants';
export type { Packet, L3Protocol } from '@/domains/acl/types';

export const WEB_PORTS = {
  HTTP: 80,
  HTTPS: 443,
  HTTP_ALT: 8080,
  HTTPS_ALT: 8443,
} as const;

export const WEB_PROTOCOLS = {
  HTTP: 'tcp',
  HTTPS: 'tcp',
} as const;

export class WebAccessService {
  private acl: AccessList;

  constructor() {
    this.acl = new AccessList();
  }

  permitHttpTraffic(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: WEB_PORTS.HTTP },
    });
  }

  permitHttpsTraffic(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.acl.addExtended(aclId, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: srcNetwork ?? '0.0.0.0',
      srcWildcard: srcWildcard ?? '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: WEB_PORTS.HTTPS },
    });
  }

  permitWebTraffic(aclId: string | number, srcNetwork?: string, srcWildcard?: string): void {
    this.permitHttpTraffic(aclId, srcNetwork, srcWildcard);
    this.permitHttpsTraffic(aclId, srcNetwork, srcWildcard);
  }

  restrictWebToNetwork(aclId: string | number, allowedNetwork: string, allowedWildcard: string): void {
    this.permitWebTraffic(aclId, allowedNetwork, allowedWildcard);
    this.acl.addExtended(aclId, {
      op: Operation.Deny,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: WEB_PORTS.HTTP },
    });
    this.acl.addExtended(aclId, {
      op: Operation.Deny,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: WEB_PORTS.HTTPS },
    });
  }

  getAccessList(): AccessList {
    return this.acl;
  }
}
