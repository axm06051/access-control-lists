import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('DNS Filtering', () => {
  describe('permit all DNS traffic', () => {
    it('permits UDP DNS queries to any server', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });

    it('permits TCP DNS queries to any server', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });
  });

  describe('permit DNS to specific servers only', () => {
    it('permits DNS to legitimate DNS servers', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.2',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.3', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });

    it('denies DNS to unauthorized servers', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '8.8.8.8', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });
  });

  describe('DNS with TCP and UDP', () => {
    it('permits both TCP and UDP DNS', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });
  });
});
