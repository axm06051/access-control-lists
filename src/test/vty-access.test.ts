import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('vty ACL Access Control', () => {
  describe('inbound vty ACL - SSH access to router', () => {
    it('permits SSH from IT subnet only', () => {
      const acl = new AccessList();
      acl.addStandard('IT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_ONLY')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_ONLY')).toBe('Deny');
    });

    it('denies SSH from other subnets', () => {
      const acl = new AccessList();
      acl.addStandard('IT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_ONLY')).toBe('Deny');
    });

    it('permits Telnet from IT subnet', () => {
      const acl = new AccessList();
      acl.addStandard('IT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 23 }, 'IT_ONLY')).toBe('Permit');
    });

    it('denies Telnet from other subnets', () => {
      const acl = new AccessList();
      acl.addStandard('IT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 23 }, 'IT_ONLY')).toBe('Deny');
    });
  });

  describe('inbound vty ACL - multiple subnets', () => {
    it('permits SSH from multiple IT subnets', () => {
      const acl = new AccessList();
      acl.addStandard('IT_STAFF', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('IT_STAFF', { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_STAFF')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_STAFF')).toBe('Permit');
    });

    it('denies SSH from non-IT subnets', () => {
      const acl = new AccessList();
      acl.addStandard('IT_STAFF', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('IT_STAFF', { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_STAFF')).toBe('Deny');
    });
  });

  describe('outbound vty ACL - SSH from router to other devices', () => {
    it('permits SSH to specific router using extended ACL', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.12.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('denies SSH to other routers using extended ACL', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.12.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '10.1.12.2', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });

    it('permits SSH to multiple allowed routers using extended ACL', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.12.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.13.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '10.1.13.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('denies SSH to non-allowed routers using extended ACL', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.12.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.1.13.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '10.1.14.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });
  });

  describe('vty ACL with standard ACL', () => {
    it('uses standard ACL for vty access', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 1)).toBe('Deny');
    });
  });

  describe('vty ACL with extended ACL', () => {
    it('uses extended ACL for vty access with port matching', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.1.12.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Deny');
    });
  });

  describe('vty ACL security best practices', () => {
    it('restricts SSH to specific management subnet', () => {
      const acl = new AccessList();
      acl.addStandard('MGMT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.50', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'MGMT_ONLY')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.50', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'MGMT_ONLY')).toBe('Deny');
    });

    it('denies all other access by default', () => {
      const acl = new AccessList();
      acl.addStandard('MGMT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'MGMT_ONLY')).toBe('Deny');
    });
  });

  describe('vty ACL for Telnet access', () => {
    it('permits Telnet from management subnet', () => {
      const acl = new AccessList();
      acl.addStandard('TELNET_MGMT', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 23 }, 'TELNET_MGMT')).toBe('Permit');
    });

    it('denies Telnet from other subnets', () => {
      const acl = new AccessList();
      acl.addStandard('TELNET_MGMT', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 23 }, 'TELNET_MGMT')).toBe('Deny');
    });
  });

  describe('vty ACL with any keyword', () => {
    it('permits SSH from any source', () => {
      const acl = new AccessList();
      acl.addStandard('OPEN', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'OPEN')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'OPEN')).toBe('Permit');
    });
  });
});
