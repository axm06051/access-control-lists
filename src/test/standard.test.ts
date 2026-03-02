import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Standard ACLs - Wildcard Masks and Subnet Matching', () => {
  describe('exact IP address matching', () => {
    it('matches exact source IP address', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.2', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('denies non-matching exact address', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '172.16.5.4', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.5.4', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.5.5', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });
  });

  describe('wildcard mask 0.0.0.255 - last octet ignored', () => {
    it('matches all addresses in /24 subnet', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches subnet 192.168.6.0/24', () => {
      const acl = new AccessList();
      acl.addStandard(2, { op: Operation.Permit, srcIp: '192.168.6.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.6.100', dstIp: '0.0.0.0' }, 2)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.7.0', dstIp: '0.0.0.0' }, 2)).toBe('Deny');
    });
  });

  describe('wildcard mask 0.0.255.255 - last two octets ignored', () => {
    it('matches all addresses in /16 subnet', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.100.50', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.255.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.169.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches subnet 10.1.0.0/16', () => {
      const acl = new AccessList();
      acl.addStandard(3, { op: Operation.Permit, srcIp: '10.1.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.50.100', dstIp: '0.0.0.0' }, 3)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.2.0.0', dstIp: '0.0.0.0' }, 3)).toBe('Deny');
    });
  });

  describe('wildcard mask 0.255.255.255 - last three octets ignored', () => {
    it('matches all addresses in /8 network', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.0.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.100.200.50', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.255.255.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '11.0.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches class A network 10.0.0.0/8', () => {
      const acl = new AccessList();
      acl.addStandard(4, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 4)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.0.0', dstIp: '0.0.0.0' }, 4)).toBe('Deny');
    });
  });

  describe('first-match logic', () => {
    it('uses first matching ACE and stops', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });

    it('matches second ACE when first does not match', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.2', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('applies implicit deny when no ACE matches', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.3.3.3', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('stops processing after first match with deny', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.5', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });
  });

  describe('any keyword matching', () => {
    it('matches any source address', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.0.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });

    it('permits all traffic with any keyword', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '0.0.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '255.255.255.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('subnet mask to wildcard mask conversion', () => {
    it('converts /24 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.200.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.201.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('converts /21 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(5, { op: Operation.Permit, srcIp: '10.1.200.0', wildcardMask: '0.0.7.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.0', dstIp: '0.0.0.0' }, 5)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.207.255', dstIp: '0.0.0.0' }, 5)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.208.0', dstIp: '0.0.0.0' }, 5)).toBe('Deny');
    });

    it('converts /27 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(6, { op: Operation.Permit, srcIp: '10.1.200.0', wildcardMask: '0.0.0.31' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.0', dstIp: '0.0.0.0' }, 6)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.31', dstIp: '0.0.0.0' }, 6)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.200.32', dstIp: '0.0.0.0' }, 6)).toBe('Deny');
    });

    it('converts /23 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(7, { op: Operation.Permit, srcIp: '172.20.112.0', wildcardMask: '0.0.1.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.112.0', dstIp: '0.0.0.0' }, 7)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.113.255', dstIp: '0.0.0.0' }, 7)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.114.0', dstIp: '0.0.0.0' }, 7)).toBe('Deny');
    });

    it('converts /26 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(8, { op: Operation.Permit, srcIp: '172.20.112.0', wildcardMask: '0.0.0.63' });

      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.112.0', dstIp: '0.0.0.0' }, 8)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.112.63', dstIp: '0.0.0.0' }, 8)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.20.112.64', dstIp: '0.0.0.0' }, 8)).toBe('Deny');
    });

    it('converts /28 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(9, { op: Operation.Permit, srcIp: '192.168.9.64', wildcardMask: '0.0.0.15' });

      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.64', dstIp: '0.0.0.0' }, 9)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.79', dstIp: '0.0.0.0' }, 9)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.80', dstIp: '0.0.0.0' }, 9)).toBe('Deny');
    });

    it('converts /30 subnet mask to wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(10, { op: Operation.Permit, srcIp: '192.168.9.64', wildcardMask: '0.0.0.3' });

      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.64', dstIp: '0.0.0.0' }, 10)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.67', dstIp: '0.0.0.0' }, 10)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.9.68', dstIp: '0.0.0.0' }, 10)).toBe('Deny');
    });
  });

  describe('named standard ACLs', () => {
    it('creates named standard ACL', () => {
      const acl = new AccessList();
      acl.addStandard('BRANCH_USERS', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.50', dstIp: '0.0.0.0' }, 'BRANCH_USERS')).toBe('Permit');
    });

    it('distinguishes between numbered and named ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('NAMED', { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.50', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.50', dstIp: '0.0.0.0' }, 'NAMED')).toBe('Deny');
    });
  });

  describe('placement strategy - near destination', () => {
    it('standard ACL near destination prevents unintended filtering', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.100', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });
  });

  describe('multiple ACEs in sequence', () => {
    it('processes multiple ACEs in order', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.2', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.3.3.3', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });
  });
});
