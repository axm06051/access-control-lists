import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Standard ACL Basics', () => {
  describe('implicit deny behavior', () => {
    it('denies traffic not explicitly permitted', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('applies implicit deny at end of ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.2.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.3.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('denies all traffic when only deny rules exist', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });
  });

  describe('ACE processing order', () => {
    it('processes ACEs from top to bottom', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('stops processing after first match', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.0.0', wildcardMask: '0.0.255.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('avoids shadowed rules by ordering correctly', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.1.100', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.50', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });
  });

  describe('source IP matching with wildcards', () => {
    it('permits single host with /32 wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.100', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.101', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('permits subnet with /24 wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.254', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('permits subnet with /16 wildcard', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.255.254', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('permits all traffic with any keyword', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '8.8.8.8', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });
  });

  describe('department-based filtering', () => {
    it('blocks engineering department from accessing server LAN', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.2.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('permits multiple departments', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.3.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.2.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.3.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.4.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });
  });

  describe('user-based filtering', () => {
    it('blocks specific users', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.10', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.11', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.10', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.11', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.50', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('permits specific users only', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.10', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.11', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.10', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.11', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.50', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });
  });

  describe('standard ACL numbering ranges', () => {
    it('uses standard ACL range 1-99', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('uses standard ACL range 1300-1999', () => {
      const acl = new AccessList();
      acl.addStandard(1300, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1300)).toBe('Permit');
    });

    it('uses standard ACL range 1999', () => {
      const acl = new AccessList();
      acl.addStandard(1999, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1999)).toBe('Permit');
    });
  });

  describe('named standard ACLs', () => {
    it('permits traffic with named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('ALLOW_ENGINEERING', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 'ALLOW_ENGINEERING')).toBe('Permit');
    });

    it('denies traffic with named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('ALLOW_ENGINEERING', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.2.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 'ALLOW_ENGINEERING')).toBe('Deny');
    });

    it('uses descriptive names for clarity', () => {
      const acl = new AccessList();
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Deny, srcIp: '192.168.1.10', wildcardMask: '0.0.0.0' });
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Deny, srcIp: '192.168.1.11', wildcardMask: '0.0.0.0' });
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.10', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 'BLOCK_MARTHA_BOB')).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.50', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 'BLOCK_MARTHA_BOB')).toBe('Permit');
    });
  });

  describe('ACL placement considerations', () => {
    it('applies outbound on destination interface', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.0.0', wildcardMask: '0.0.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.100', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
    });

    it('applies inbound on source interface', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.10', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.11', wildcardMask: '0.0.0.0' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.10', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.50', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });
  });

  describe('edge cases and boundary conditions', () => {
    it('handles 0.0.0.0 source address', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '0.0.0.0', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('handles 255.255.255.255 broadcast address', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '255.255.255.255', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '255.255.255.255', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });

    it('handles maximum wildcard mask', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 1)).toBe('Permit');
    });
  });
});
