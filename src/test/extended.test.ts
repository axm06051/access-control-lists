import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('Extended ACLs - Protocol and Port Matching', () => {
  describe('protocol matching - TCP', () => {
    it('matches TCP packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'tcp', ...ANY });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });

    it('denies non-TCP packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'tcp', ...ANY });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.1.1', dstIp: '10.2.2.1' }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.1.1', dstIp: '10.2.2.1' }, 100)).toBe('Deny');
    });
  });

  describe('protocol matching - UDP', () => {
    it('matches UDP packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'udp', ...ANY });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('protocol matching - ICMP', () => {
    it('matches ICMP packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'icmp', ...ANY });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.1.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('protocol matching - OSPF', () => {
    it('matches OSPF packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ospf', ...ANY });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.12.1', dstIp: '224.0.0.5', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('protocol matching - IP (all)', () => {
    it('matches all IP packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.1.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.1.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
    });
  });

  describe('source and destination IP matching', () => {
    it('matches specific source and destination IPs', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.1',
        srcWildcard: '0.0.0.0',
        dstIp: '10.2.2.1',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.2', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('matches source subnet and destination subnet', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.5.100', dstIp: '10.2.19.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.6.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('matches any source and specific destination', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.2.1',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('destination port matching - HTTP', () => {
    it('matches HTTP destination port 80', () => {
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

    it('matches HTTPS destination port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('source port matching', () => {
    it('matches FTP source port 21', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 21 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 21, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 80, dstPort: 49160 }, 100)).toBe('Deny');
    });

    it('matches Telnet source port 23', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 23 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 23, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 22, dstPort: 49160 }, 100)).toBe('Deny');
    });
  });

  describe('port range matching', () => {
    it('matches port range for ephemeral ports', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'range', portA: 49152, portB: 65535 },
        dstIp: '10.1.1.1',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.1.1', srcPort: 65535, dstPort: 23 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.1.1.1', srcPort: 49151, dstPort: 23 }, 100)).toBe('Deny');
    });
  });

  describe('all parameters must match', () => {
    it('requires protocol match', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('requires source IP match', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.2.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('requires destination IP match', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.3.3.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('requires port match when specified', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });
  });

  describe('first-match logic with extended ACLs', () => {
    it('uses first matching ACE', () => {
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
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
    });

    it('stops processing after first match', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.1.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.2.2.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('named extended ACLs', () => {
    it('creates named extended ACL', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.100', dstIp: '10.2.16.50', srcPort: 49160, dstPort: 80 }, 'BRANCH_WAN')).toBe('Permit');
    });
  });

  describe('placement strategy - near source', () => {
    it('extended ACL near source saves bandwidth', () => {
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

  describe('HTTP/3 with UDP port 443', () => {
    it('matches HTTP/3 traffic on UDP port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        srcPort: { op: 'eq', port: 443 },
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.50', dstIp: '10.1.4.100', srcPort: 443, dstPort: 49160 }, 100)).toBe('Deny');
    });
  });
});
