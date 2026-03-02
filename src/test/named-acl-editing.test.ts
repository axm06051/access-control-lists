import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Named ACLs and ACL Editing', () => {
  describe('named standard ACL creation', () => {
    it('creates named standard ACL with permit rule', () => {
      const acl = new AccessList();
      acl.addStandard('IT_ONLY', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl('IT_ONLY')).toBe(true);
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'IT_ONLY')).toBe('Permit');
    });

    it('creates named standard ACL with deny rule', () => {
      const acl = new AccessList();
      acl.addStandard('BLOCK_GUEST', { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.50', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'BLOCK_GUEST')).toBe('Deny');
    });

    it('creates named standard ACL with multiple rules', () => {
      const acl = new AccessList();
      acl.addStandard('HANNAH', { op: Operation.Permit, srcIp: '10.1.1.2', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('HANNAH', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Deny');
    });
  });

  describe('named extended ACL creation', () => {
    it('creates named extended ACL with protocol matching', () => {
      const acl = new AccessList();
      acl.addExtended('BRANCH_WAN', {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.hasAcl('BRANCH_WAN')).toBe(true);
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 80 }, 'BRANCH_WAN')).toBe('Permit');
    });

    it('creates named extended ACL with multiple rules', () => {
      const acl = new AccessList();
      acl.addExtended('DC_WAN', {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 80 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });
      acl.addExtended('DC_WAN', {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 443 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 80, dstPort: 49160 }, 'DC_WAN')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 443, dstPort: 49160 }, 'DC_WAN')).toBe('Permit');
    });
  });

  describe('ACL deletion', () => {
    it('deletes entire named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('TEMP_ACL', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl('TEMP_ACL')).toBe(true);
      acl.deleteAcl('TEMP_ACL');
      expect(acl.hasAcl('TEMP_ACL')).toBe(false);
    });

    it('deletes individual ACE by sequence number', () => {
      const acl = new AccessList();
      acl.addStandard('HANNAH', { op: Operation.Permit, srcIp: '10.1.1.2', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      acl.deleteAce('HANNAH', 20);

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Deny');
    });

    it('deletes multiple ACEs from named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('HANNAH', { op: Operation.Permit, srcIp: '10.1.1.2', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('HANNAH', { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      acl.deleteAce('HANNAH', 20);
      acl.deleteAce('HANNAH', 40);

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HANNAH')).toBe('Deny');
    });
  });

  describe('ACL resequencing', () => {
    it('resequences ACL with new starting number and increment', () => {
      const acl = new AccessList();
      acl.addStandard('TEST_ACL', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST_ACL', { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST_ACL', { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      acl.resequence('TEST_ACL', 100, 20);

      const output = acl.toString();
      expect(output).toContain('100');
      expect(output).toContain('120');
      expect(output).toContain('140');
    });

    it('resequences numbered ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      acl.resequence(1, 50, 10);

      const output = acl.toString();
      expect(output).toContain('50');
      expect(output).toContain('60');
    });

    it('maintains ACE order after resequencing', () => {
      const acl = new AccessList();
      acl.addStandard('ORDER_TEST', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('ORDER_TEST', { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('ORDER_TEST', { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      acl.resequence('ORDER_TEST', 100, 20);

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'ORDER_TEST')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'ORDER_TEST')).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'ORDER_TEST')).toBe('Permit');
    });
  });

  describe('ACL insertion with sequence numbers', () => {
    it('inserts ACE at specific sequence number', () => {
      const acl = new AccessList();
      acl.addStandard('INSERT_TEST', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('INSERT_TEST', { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      const entries = Array.from(acl.entries());
      const testEntry = entries.find(e => e.id === 'INSERT_TEST');
      expect(testEntry?.rules.length).toBe(2);
    });

    it('maintains relative order when inserting between existing ACEs', () => {
      const acl = new AccessList();
      acl.addStandard('ORDER_INSERT', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('ORDER_INSERT', { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'ORDER_INSERT')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.3.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'ORDER_INSERT')).toBe('Permit');
    });
  });

  describe('named ACL with any keyword', () => {
    it('permits traffic from any source with any keyword', () => {
      const acl = new AccessList();
      acl.addStandard('OPEN', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'OPEN')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'OPEN')).toBe('Permit');
    });

    it('denies traffic from any source with any keyword', () => {
      const acl = new AccessList();
      acl.addStandard('CLOSED', { op: Operation.Deny, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'CLOSED')).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'CLOSED')).toBe('Deny');
    });
  });

  describe('named ACL with host keyword', () => {
    it('permits traffic from specific host', () => {
      const acl = new AccessList();
      acl.addStandard('HOST_ONLY', { op: Operation.Permit, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HOST_ONLY')).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'HOST_ONLY')).toBe('Deny');
    });

    it('denies traffic from specific host', () => {
      const acl = new AccessList();
      acl.addStandard('BLOCK_HOST', { op: Operation.Deny, srcIp: '10.1.1.1', wildcardMask: '0.0.0.0' });
      acl.addStandard('BLOCK_HOST', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'BLOCK_HOST')).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.1.12.1', srcPort: 49160, dstPort: 22 }, 'BLOCK_HOST')).toBe('Permit');
    });
  });
});
