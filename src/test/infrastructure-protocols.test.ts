import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Infrastructure Protocols Filtering', () => {
  describe('Example 8-1: Permitting All DNS Traffic', () => {
    it('permits UDP DNS to any server on port 53', () => {
      const acl = new AccessList();
      acl.addExtended(50, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 50)).toBe('Permit');
    });

    it('permits TCP DNS to any server on port 53', () => {
      const acl = new AccessList();
      acl.addExtended(60, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 60)).toBe('Permit');
    });
  });

  describe('Example 8-2: Permitting DNS to Specific Servers Only', () => {
    it('permits UDP DNS to legitimate server 10.2.32.1', () => {
      const acl = new AccessList();
      acl.addExtended(110, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 110)).toBe('Permit');
    });

    it('permits UDP DNS to legitimate server 10.2.32.2', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.2',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.3', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });

    it('denies DNS to unauthorized servers', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '8.8.8.8', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });
  });

  describe('ICMP filtering', () => {
    it('permits all ICMP messages', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.1.4.2' }, 100)).toBe('Permit');
    });

    it('permits ICMP within private network only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.1.4.2' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '8.8.8.8', dstIp: '10.1.4.1' }, 100)).toBe('Deny');
    });

    it('denies ICMP from external networks', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '8.8.8.8', dstIp: '10.1.4.1' }, 100)).toBe('Deny');
    });
  });

  describe('OSPF filtering', () => {
    it('permits all OSPF messages', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('permits OSPF from known neighbor only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.3', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });

    it('denies OSPF from unauthorized neighbors', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.3', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });

    it('permits OSPF to multicast address', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '224.0.0.5',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });
  });

  describe('DHCP filtering', () => {
    it('permits DHCP to server port 67', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
    });

    it('permits DHCP to specific server only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.16.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.2', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });

    it('denies DHCP to unauthorized servers', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.16.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '192.168.1.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });

    it('permits DHCP client port 68', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.1',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 68 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.254', srcPort: 67, dstPort: 68 }, 100)).toBe('Permit');
    });
  });

  describe('SSH and Telnet filtering', () => {
    it('permits SSH on port 22', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('permits Telnet on port 23', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
    });

    it('permits SSH and Telnet from private network only', () => {
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
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
        dstPort: { op: 'eq', port: 23 },
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '8.8.8.8', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });

    it('permits SSH responses from server with source port 22', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.0.255',
        srcPort: { op: 'eq', port: 22 },
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.1.100', srcPort: 22, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('mixed infrastructure protocol filtering', () => {
    it('permits DNS, DHCP, and OSPF together', () => {
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
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies non-infrastructure protocols', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });
});

  describe('mixed infrastructure protocol filtering', () => {
    it('permits DNS, DHCP, and OSPF together', () => {
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
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies non-infrastructure protocols', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('branch office common ACL scenario', () => {
    it('permits all infrastructure protocols for branch router', () => {
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
        protocol: 'tcp',
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
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.1.4.2' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });
  });

  describe('ICMP echo and time exceeded filtering', () => {
    it('permits ICMP echo request and reply within private network', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.1.4.2' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '8.8.8.8', dstIp: '10.1.4.1' }, 100)).toBe('Deny');
    });

    it('permits traceroute with ICMP time exceeded', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.1.4.2' }, 100)).toBe('Permit');
    });
  });

  describe('DHCP helper function interaction', () => {
    it('permits DHCP discover from broadcast address', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '255.255.255.255',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '0.0.0.0', dstIp: '255.255.255.255', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
    });

    it('permits DHCP after helper address transformation', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.1.4.254',
        srcWildcard: '0.0.0.0',
        dstIp: '10.2.16.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
    });

    it('denies DHCP to unauthorized servers after helper transformation', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.1.4.254',
        srcWildcard: '0.0.0.0',
        dstIp: '10.2.16.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.2', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });
  });

  describe('SSH and Telnet bidirectional filtering', () => {
    it('permits SSH to server with destination port 22', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
    });

    it('permits SSH response from server with source port 22', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        srcPort: { op: 'eq', port: 22 },
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.1.100', srcPort: 22, dstPort: 49160 }, 100)).toBe('Permit');
    });

    it('permits both SSH directions with separate ACEs', () => {
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
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        srcPort: { op: 'eq', port: 22 },
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.100', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.1.100', srcPort: 22, dstPort: 49160 }, 100)).toBe('Permit');
    });

    it('denies SSH from external networks', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '8.8.8.8', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 22 }, 100)).toBe('Deny');
    });
  });

  describe('complex multi-protocol ACL scenario', () => {
    it('permits infrastructure protocols and denies user traffic', () => {
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
        protocol: 'tcp',
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
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
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
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });
  });

  describe('OSPF neighbor filtering', () => {
    it('permits OSPF from specific neighbor only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.3', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });

    it('permits OSPF to multicast address 224.0.0.5', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.0',
        srcWildcard: '0.0.0.255',
        dstIp: '224.0.0.5',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies OSPF to non-multicast addresses', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.0',
        srcWildcard: '0.0.0.255',
        dstIp: '224.0.0.5',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '10.1.12.1' }, 100)).toBe('Deny');
    });
  });

  describe('DNS server protection', () => {
    it('permits DNS to legitimate servers only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.2',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.2',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.32.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '10.2.32.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '8.8.8.8', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.4.1', dstIp: '8.8.8.8', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });
  });

  describe('DHCP server protection', () => {
    it('permits DHCP to legitimate server only', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.16.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '192.168.1.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });

    it('permits DHCP client responses on port 68', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.1',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 68 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.254', srcPort: 67, dstPort: 68 }, 100)).toBe('Permit');
    });
  });
