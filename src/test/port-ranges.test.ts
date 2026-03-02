import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Port Ranges and Operators', () => {
  describe('well-known ports (0-1023)', () => {
    it('permits traffic to well-known port 80 (HTTP)', () => {
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

    it('permits traffic to well-known port 443 (HTTPS)', () => {
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

    it('permits traffic to well-known port 25 (SMTP)', () => {
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

    it('permits traffic to well-known port 110 (POP3)', () => {
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

    it('permits traffic to well-known port 143 (IMAP)', () => {
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

    it('permits traffic to well-known port 20 (FTP data)', () => {
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

    it('permits traffic to well-known port 21 (FTP control)', () => {
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
  });

  describe('registered ports (1024-49151)', () => {
    it('permits traffic to registered port 3306 (MySQL)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 3306 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 3306 }, 100)).toBe('Permit');
    });

    it('permits traffic to registered port 5432 (PostgreSQL)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 5432 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 5432 }, 100)).toBe('Permit');
    });

    it('permits traffic to registered port 8080 (HTTP alternate)', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 8080 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 8080 }, 100)).toBe('Permit');
    });
  });

  describe('ephemeral ports (49152-65535)', () => {
    it('permits traffic from ephemeral source port', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 50000 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 50000, dstPort: 80 }, 100)).toBe('Permit');
    });

    it('permits traffic from ephemeral port range', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 50000, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 65535, dstPort: 80 }, 100)).toBe('Permit');
    });
  });

  describe('port operators - eq (equal)', () => {
    it('permits traffic matching exact port with eq operator', () => {
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

    it('denies traffic not matching exact port with eq operator', () => {
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

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('port operators - range', () => {
    it('permits traffic within port range', () => {
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
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 200 }, 100)).toBe('Permit');
    });

    it('denies traffic outside port range', () => {
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
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 3306 }, 100)).toBe('Deny');
    });

    it('permits traffic at range boundaries', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'range', portA: 1024, portB: 49151 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 1024 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 49151 }, 100)).toBe('Permit');
    });
  });

  describe('port operators - gt (greater than)', () => {
    it('permits traffic with port greater than specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'gt', port: 1023 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 1024 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 3306 }, 100)).toBe('Permit');
    });

    it('denies traffic with port not greater than specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'gt', port: 1023 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 1023 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });
  });

  describe('port operators - lt (less than)', () => {
    it('permits traffic with port less than specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'lt', port: 1024 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 1023 }, 100)).toBe('Permit');
    });

    it('denies traffic with port not less than specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'lt', port: 1024 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 1024 }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 3306 }, 100)).toBe('Deny');
    });
  });

  describe('port operators - neq (not equal)', () => {
    it('permits traffic with port not equal to specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'neq', port: 23 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies traffic with port equal to specified', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'neq', port: 23 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 23 }, 100)).toBe('Deny');
    });
  });

  describe('bidirectional port matching', () => {
    it('permits traffic matching both source and destination ports', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 49160 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 80 }, 100)).toBe('Permit');
    });

    it('denies traffic not matching source port', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 49160 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49161, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('denies traffic not matching destination port', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        srcPort: { op: 'eq', port: 49160 },
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.1.1.1', dstIp: '10.2.2.2', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });
  });
});
