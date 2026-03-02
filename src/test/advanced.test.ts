import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('AccessList. Advanced Operations', () => {
  describe('resequence', () => {
    it('resequences ACE numbers starting from custom value', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.3.0', wildcardMask: '0.0.0.255' });

      acl.resequence(1, 100, 5);
      const output = acl.toString();

      expect(output).toContain('100');
      expect(output).toContain('105');
      expect(output).toContain('110');
    });

    it('resequences with increment of 1', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      acl.resequence(1, 50, 1);
      const output = acl.toString();

      expect(output).toContain('50');
      expect(output).toContain('51');
    });

    it('throws error when resequencing non-existent ACL', () => {
      const acl = new AccessList();
      expect(() => acl.resequence(999, 10, 10)).toThrow(RangeError);
    });

    it('resequences named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      acl.resequence('TEST', 200, 10);
      const output = acl.toString();

      expect(output).toContain('200');
      expect(output).toContain('210');
    });
  });

  describe('entries', () => {
    it('returns iterator of all ACL entries', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(2, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });

      const entries = Array.from(acl.entries());
      expect(entries.length).toBe(3);
    });

    it('entries iterator includes all rules', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      const entries = Array.from(acl.entries());
      expect(entries[0]?.rules.length).toBe(2);
    });

    it('entries iterator is empty for new ACL', () => {
      const acl = new AccessList();
      const entries = Array.from(acl.entries());
      expect(entries.length).toBe(0);
    });

    it('entries can be iterated multiple times', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      const first = Array.from(acl.entries());
      const second = Array.from(acl.entries());

      expect(first.length).toBe(second.length);
      expect(first[0]?.id).toBe(second[0]?.id);
    });
  });

  describe('hasAcl', () => {
    it('returns true for existing numbered ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      expect(acl.hasAcl(1)).toBe(true);
    });

    it('returns true for existing named ACL', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      expect(acl.hasAcl('TEST')).toBe(true);
    });

    it('returns false for non-existent ACL', () => {
      const acl = new AccessList();
      expect(acl.hasAcl(999)).toBe(false);
      expect(acl.hasAcl('NONEXISTENT')).toBe(false);
    });

    it('returns false after deleting ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      expect(acl.hasAcl(1)).toBe(true);

      acl.deleteAcl(1);
      expect(acl.hasAcl(1)).toBe(false);
    });

    it('distinguishes between numbered and named ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('1', { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl(1)).toBe(true);
      expect(acl.hasAcl('1')).toBe(true);
    });
  });

  describe('showAcl', () => {
    it('returns formatted ACL output', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl(1);
      expect(output).toContain('Standard IP Access List 1');
      expect(output).toContain('Permit');
    });

    it('returns error message for non-existent ACL', () => {
      const acl = new AccessList();
      const output = acl.showAcl(999);
      expect(output).toContain('not found');
    });

    it('shows all rules in ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl(1);
      expect(output).toContain('Permit');
      expect(output).toContain('Deny');
    });

    it('shows named ACL correctly', () => {
      const acl = new AccessList();
      acl.addStandard('MY_ACL', { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      const output = acl.showAcl('MY_ACL');
      expect(output).toContain('MY_ACL');
    });
  });

  describe('toString with custom marker', () => {
    it('uses default marker when not specified', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('Standard IP Access List 1');
    });

    it('uses custom marker in output', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString('>>');
      expect(output).toContain('>>');
    });

    it('applies marker to all rules', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString('***');
      const lines = output.split('\n');
      const ruleLines = lines.filter((l) => l.startsWith('***'));
      expect(ruleLines.length).toBe(2);
    });

    it('includes all ACLs in toString', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });

      const output = acl.toString();
      expect(output).toContain('Standard IP Access List 1');
      expect(output).toContain('Extended IP Access List 100');
    });
  });

  describe('setIncrement', () => {
    it('changes sequence number increment', () => {
      const acl = new AccessList();
      acl.setIncrement(5);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('5');
      expect(output).toContain('10');
    });

    it('increment applies to subsequent additions', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

      acl.setIncrement(25);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('10');
      expect(output).toContain('35');
    });

    it('increment of 1 creates sequential numbers', () => {
      const acl = new AccessList();
      acl.setIncrement(1);
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.3.0', wildcardMask: '0.0.0.255' });

      const output = acl.toString();
      expect(output).toContain('1');
      expect(output).toContain('2');
      expect(output).toContain('3');
    });
  });

  describe('multiple ACLs in single registry', () => {
    it('maintains separate rules for different ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(2, { op: Operation.Deny, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.1.5', dstIp: '0.0.0.0' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.2.5', dstIp: '0.0.0.0' }, 2)).toBe('Deny');
    });

    it('allows mixed numbered and named ACLs', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('NAMED', { op: Operation.Deny, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      expect(acl.hasAcl(1)).toBe(true);
      expect(acl.hasAcl('NAMED')).toBe(true);
    });

    it('deleteAcl removes only specified ACL', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(2, { op: Operation.Permit, srcIp: '192.168.2.0', wildcardMask: '0.0.0.255' });

      acl.deleteAcl(1);

      expect(acl.hasAcl(1)).toBe(false);
      expect(acl.hasAcl(2)).toBe(true);
    });
  });
});
