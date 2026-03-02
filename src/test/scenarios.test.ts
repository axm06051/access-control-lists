import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('Complex ACL Scenarios', () => {
  describe('scenario 1: branch office filtering', () => {
    it('permits HTTP/HTTPS to data center web servers', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.5.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies non-HTTP/HTTPS traffic', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });
  });

  describe('scenario 2: infrastructure protocol protection', () => {
    it('permits essential infrastructure protocols', () => {
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
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });
  });

  describe('scenario 3: server response filtering', () => {
    it('permits web server responses to clients', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 80 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 443 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 80, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.5.100', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('scenario 4: multi-protocol filtering', () => {
    it('permits multiple protocols with specific rules', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 443 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 22 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });
  });

  describe('scenario 5: deny specific traffic while permitting rest', () => {
    it('denies specific source then permits others', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '10.1.4.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.2', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
    });
  });

  describe('scenario 6: standard ACL near destination', () => {
    it('permits traffic from specific subnet near destination', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '10.1.1.0', wildcardMask: '0.0.0.255' });

      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.1.100', dstIp: '10.2.2.1' }, 1)).toBe('Permit');
      expect(acl.validate({ protocol: 'ip', srcIp: '10.1.2.100', dstIp: '10.2.2.1' }, 1)).toBe('Deny');
    });
  });

  describe('scenario 7: extended ACL near source', () => {
    it('filters traffic near source for efficiency', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });
  });

  describe('scenario 8: HTTP/3 support', () => {
    it('permits both TCP and UDP web traffic', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 443 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 443 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('scenario 9: first-match logic importance', () => {
    it('demonstrates why ACE order matters', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('shows permit before deny allows traffic', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
    });
  });

  describe('scenario 10: implicit deny any', () => {
    it('denies traffic not explicitly permitted', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });
});
