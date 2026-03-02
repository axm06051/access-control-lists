import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('TCP/IP Transport and Applications', () => {
  describe('TCP protocol matching', () => {
    it('matches TCP packets with destination port 80 (HTTP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });

    it('matches TCP packets with destination port 443 (HTTPS)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('matches TCP packets with destination port 25 (SMTP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 25 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 25 }, 100)).toBe('Permit');
    });

    it('matches TCP packets with destination port 110 (POP3)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 110 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 110 }, 100)).toBe('Permit');
    });

    it('matches TCP packets with destination port 143 (IMAP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 143 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 143 }, 100)).toBe('Permit');
    });
  });

  describe('UDP protocol matching', () => {
    it('matches UDP packets with destination port 53 (DNS)', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });

    it('matches UDP packets with destination port 67 (DHCP Server)', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
    });

    it('matches UDP packets with destination port 68 (DHCP Client)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 68 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '192.168.1.1', srcPort: 67, dstPort: 68 }, 100)).toBe('Permit');
    });

    it('matches UDP packets with destination port 69 (TFTP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 69 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 69 }, 100)).toBe('Permit');
    });

    it('matches UDP packets with destination port 161 (SNMP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 161 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 161 }, 100)).toBe('Permit');
    });

    it('matches UDP packets with destination port 514 (Syslog)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 514 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 514 }, 100)).toBe('Permit');
    });
  });

  describe('well-known port ranges', () => {
    it('matches ephemeral port range 49152-65535', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'range', portA: 49152, portB: 65535 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 65535, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49151, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('matches registered port range 1024-49151', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'range', portA: 1024, portB: 49151 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 8080, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 1024, dstPort: 80 }, 100)).toBe('Permit');
    });

    it('matches well-known port range 0-1023', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'range', portA: 0, portB: 1023 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 80, dstPort: 49160 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });

  describe('TCP vs UDP differentiation', () => {
    it('denies UDP when TCP is required', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('denies TCP when UDP is required', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Deny');
    });

    it('permits both TCP and UDP with ip protocol', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ip',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.1.1', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });
  });

  describe('application layer protocols', () => {
    it('permits web traffic (HTTP and HTTPS)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.100', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.100', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('permits email traffic (SMTP, POP3, IMAP)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 25 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 110 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.1.1.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 143 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.100', srcPort: 49160, dstPort: 25 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.100', srcPort: 49160, dstPort: 110 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.1', dstIp: '10.1.1.100', srcPort: 49160, dstPort: 143 }, 100)).toBe('Permit');
    });
  });
});
