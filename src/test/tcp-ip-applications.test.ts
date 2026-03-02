import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('TCP/IP Applications', () => {
  describe('HTTP and HTTPS applications', () => {
    it('permits HTTP traffic on port 80', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
    });

    it('permits HTTPS traffic on port 443', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('permits both HTTP and HTTPS traffic', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'range', portA: 80, portB: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies non-HTTP/HTTPS traffic', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'range', portA: 80, portB: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 25 }, 100)).toBe('Deny');
    });
  });

  describe('Email applications', () => {
    it('permits SMTP traffic on port 25', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 25 }, 100)).toBe('Permit');
    });

    it('permits POP3 traffic on port 110', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 110 }, 100)).toBe('Permit');
    });

    it('permits IMAP traffic on port 143', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 143 }, 100)).toBe('Permit');
    });

    it('permits all email protocols together', () => {
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
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 110 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 143 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 25 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 110 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 143 }, 100)).toBe('Permit');
    });
  });

  describe('File transfer applications', () => {
    it('permits FTP control on port 21', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 21 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 21 }, 100)).toBe('Permit');
    });

    it('permits FTP data on port 20', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 20 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 20 }, 100)).toBe('Permit');
    });

    it('permits TFTP on port 69', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 69 }, 100)).toBe('Permit');
    });

    it('permits both FTP control and data', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'range', portA: 20, portB: 21 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 20 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 21 }, 100)).toBe('Permit');
    });
  });

  describe('Remote access applications', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
    });

    it('permits SSH and Telnet together', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'range', portA: 22, portB: 23 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 22 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 23 }, 100)).toBe('Permit');
    });
  });

  describe('DNS and DHCP applications', () => {
    it('permits DNS on port 53 TCP', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });

    it('permits DNS on port 53 UDP', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });

    it('permits DHCP server on port 67', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 67 }, 100)).toBe('Permit');
    });

    it('permits DHCP client on port 68', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 68 }, 100)).toBe('Permit');
    });
  });

  describe('Network management applications', () => {
    it('permits NTP on port 123', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 123 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 123 }, 100)).toBe('Permit');
    });

    it('permits SNMP agent on port 161', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 161 }, 100)).toBe('Permit');
    });

    it('permits SNMP manager on port 162', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 162 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 162 }, 100)).toBe('Permit');
    });

    it('permits Syslog on port 514', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 514 }, 100)).toBe('Permit');
    });
  });

  describe('TCP vs UDP application requirements', () => {
    it('permits DNS on both TCP and UDP', () => {
      const acl = new AccessList();
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
        dstPort: { op: 'eq', port: 53 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 53 }, 100)).toBe('Permit');
    });

    it('denies wrong protocol for application', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });
});
