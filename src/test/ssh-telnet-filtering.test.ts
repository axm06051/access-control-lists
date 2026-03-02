import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('SSH and Telnet Filtering', () => {
  describe('permit SSH and Telnet to servers', () => {
    it('permits SSH destination port 22', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('permits Telnet destination port 23', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 23 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
    });
  });

  describe('permit SSH and Telnet from private network only', () => {
    it('permits SSH from private network', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('denies SSH from external network', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
        dstPort: { op: 'eq', port: 22 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });
  });

  describe('SSH and Telnet source port matching', () => {
    it('permits SSH source port 22 from server', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.0.255',
        srcPort: { op: 'eq', port: 22 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 22, dstPort: 49160 }, 100)).toBe('Permit');
    });

    it('permits Telnet source port 23 from server', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.0.255',
        srcPort: { op: 'eq', port: 23 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 23, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('bidirectional SSH and Telnet', () => {
    it('permits SSH in both directions', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 22 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 22 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 22, dstPort: 49160 }, 100)).toBe('Permit');
    });

    it('permits Telnet in both directions', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 23 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 23 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 23, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('vty ACL for router access', () => {
    it('permits SSH to router from specific subnet', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 1)).toBe('Deny');
    });

    it('denies SSH to router from other subnets', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 1)).toBe('Deny');
    });
  });

  describe('SSH and Telnet port range', () => {
    it('permits SSH and Telnet with port range', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
        dstPort: { op: 'range', portA: 22, portB: 23 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
    });
  });
});
