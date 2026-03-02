import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Basic IPv4 Access Control Lists', () => {
  describe('ACL numbering ranges', () => {
    it('uses standard ACL number range 1-99', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(99, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl(1)).toBe(true);
      expect(acl.hasAcl(99)).toBe(true);
    });

    it('uses standard ACL number range 1300-1999', () => {
      const acl = new AccessList();
      acl.addStandard(1300, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1999, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl(1300)).toBe(true);
      expect(acl.hasAcl(1999)).toBe(true);
    });

    it('uses extended ACL number range 100-199', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended(199, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.2.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.3.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.hasAcl(100)).toBe(true);
      expect(acl.hasAcl(199)).toBe(true);
    });

    it('uses extended ACL number range 2000-2699', () => {
      const acl = new AccessList();
      acl.addExtended(2000, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended(2699, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.2.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.3.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.hasAcl(2000)).toBe(true);
      expect(acl.hasAcl(2699)).toBe(true);
    });
  });

  describe('ACL matching logic', () => {
    it('uses first-match logic for permit', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });

    it('uses first-match logic for deny', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('applies implicit deny any at end', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.2.2.100', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });
  });

  describe('wildcard mask matching', () => {
    it('matches exact host with wildcard 0.0.0.0', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.2', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches subnet with wildcard 0.0.0.255', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches larger subnet with wildcard 0.0.1.255', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.0.0', wildcardMask: '0.0.1.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.0.0', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.255', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.0', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('matches any address with wildcard 255.255.255.255', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '172.16.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('ACL placement strategy', () => {
    it('standard ACL placed near destination', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '10.2.2.1' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.100', dstIp: '10.2.2.1' }, 1)).toBe('Deny');
    });

    it('extended ACL placed near source', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('sequence numbers', () => {
    it('assigns sequence numbers in increments of 10', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('10');
      expect(output).toContain('20');
      expect(output).toContain('30');
    });

    it('allows custom sequence numbers', () => {
      const acl = new AccessList();
      acl.setIncrement(5);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('5');
      expect(output).toContain('10');
    });
  });

  describe('multiple ACLs', () => {
    it('maintains separate ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(2, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 2)).toBe('Deny');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.100', dstIp: '0.0.0.0' }, 2)).toBe('Permit');
    });

    it('allows both numbered and named ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('NAMED_ACL', { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl(1)).toBe(true);
      expect(acl.hasAcl('NAMED_ACL')).toBe(true);
    });
  });

  describe('deny and permit logic', () => {
    it('explicit deny takes precedence', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.2', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });

    it('permit any allows all remaining traffic', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.2.2.100', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('ACL verification', () => {
    it('shows ACL with all rules', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl(1);
      expect(output).toContain('Standard IP Access List 1');
      expect(output).toContain('Permit');
      expect(output).toContain('Deny');
    });

    it('displays error for non-existent ACL', () => {
      const acl = new AccessList();
      const output = acl.showAcl(999);
      expect(output).toContain('not found');
    });
  });
});
