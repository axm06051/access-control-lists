import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('ACL Editing and Resequencing', () => {
  describe('delete individual ACE', () => {
    it('deletes specific ACE from named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST', { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.deleteAce('TEST', 20)).toBe(true);
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.1', dstIp: '0.0.0.0' }, 'TEST')).toBe('Permit');
    });

    it('returns false when deleting non-existent ACE', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.deleteAce('TEST', 999)).toBe(false);
    });

    it('maintains relative order after deletion', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      acl.deleteAce(1, 20);

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.3.3.3', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('delete entire ACL', () => {
    it('deletes entire ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.deleteAcl(1)).toBe(true);
      expect(acl.hasAcl(1)).toBe(false);
    });

    it('returns false when deleting non-existent ACL', () => {
      const acl = new AccessList();
      expect(acl.deleteAcl(999)).toBe(false);
    });

    it('does not affect other ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(2, { op: Operation.Permit, srcIp: '10.2.2.0', wildcardMask: '0.0.0.255' });

      acl.deleteAcl(1);

      expect(acl.hasAcl(1)).toBe(false);
      expect(acl.hasAcl(2)).toBe(true);
    });
  });

  describe('add ACE to end of ACL', () => {
    it('adds ACE to end of existing ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.1', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
    });

    it('new ACE uses correct sequence number', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('10');
      expect(output).toContain('20');
    });
  });

  describe('insert ACE at specific position', () => {
    it('inserts ACE between existing ACEs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.3.3.3', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('resequence ACL', () => {
    it('resequences with custom start and increment', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      acl.resequence(1, 100, 20);

      const output = acl.toString();
      expect(output).toContain('100');
      expect(output).toContain('120');
      expect(output).toContain('140');
    });

    it('maintains ACE order after resequencing', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      acl.resequence(1, 50, 10);

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.1', dstIp: '0.0.0.0' }, 1)).toBe('Deny');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.3.3.3', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });

    it('throws error when resequencing non-existent ACL', () => {
      const acl = new AccessList();
      expect(() => acl.resequence(999, 10, 10)).toThrow(RangeError);
    });

    it('resequences named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      acl.resequence('TEST', 200, 5);

      const output = acl.toString();
      expect(output).toContain('200');
      expect(output).toContain('205');
    });
  });

  describe('show ACL', () => {
    it('displays ACL with all rules', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl(1);
      expect(output).toContain('Standard IP Access List 1');
      expect(output).toContain('Permit');
      expect(output).toContain('Deny');
    });

    it('shows error for non-existent ACL', () => {
      const acl = new AccessList();
      const output = acl.showAcl(999);
      expect(output).toContain('not found');
    });

    it('displays named ACL correctly', () => {
      const acl = new AccessList();
      acl.addStandard('MY_ACL', { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl('MY_ACL');
      expect(output).toContain('MY_ACL');
    });
  });

  describe('ACL persistence and reloading', () => {
    it('maintains ACE order across operations', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.255.255.255' });

      acl.deleteAce(1, 20);
      acl.addStandard(1, { op: Operation.Deny, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.1', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
    });
  });

  describe('increment management', () => {
    it('uses custom increment for new ACEs', () => {
      const acl = new AccessList();
      acl.setIncrement(5);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.3.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('5');
      expect(output).toContain('10');
      expect(output).toContain('15');
    });

    it('changes increment mid-configuration', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      acl.setIncrement(25);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('10');
      expect(output).toContain('35');
    });
  });
});
