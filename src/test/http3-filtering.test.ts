import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('HTTP/3 Filtering with UDP', () => {
  describe('HTTP/3 traffic matching', () => {
    it('permits HTTP/3 traffic on UDP port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies non-HTTP/3 UDP traffic on port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });

    it('permits both TCP HTTPS and UDP HTTP/3 on port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'tcp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies HTTP/3 from unauthorized source', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.20.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });

    it('denies HTTP/3 to unauthorized destination', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.6.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Deny');
    });

    it('permits HTTP/3 from multiple source subnets', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.32.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.32.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('denies HTTP/3 on non-443 UDP ports', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 49160, dstPort: 80 }, 100)).toBe('Deny');
    });

    it('permits HTTP/3 with any source port', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.2.16.0',
        srcWildcard: '0.0.3.255',
        dstIp: '10.1.4.0',
        dstWildcard: '0.0.1.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 12345, dstPort: 443 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 54321, dstPort: 443 }, 100)).toBe('Permit');
    });
  });

  describe('HTTP/3 with source port matching', () => {
    it('permits HTTP/3 responses from server with source port 443', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
    });

    it('denies HTTP/3 responses from non-server source port', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 80, dstPort: 49160 }, 100)).toBe('Deny');
    });
  });

  describe('HTTP/3 bidirectional filtering', () => {
    it('permits HTTP/3 requests to server on port 443', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.1.255',
        dstIp: '10.2.16.0',
        dstWildcard: '0.0.3.255',
        dstPort: { op: 'eq', port: 443 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 49160, dstPort: 443 }, 100)).toBe('Permit');
    });

    it('permits HTTP/3 responses from server with source port 443', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 443, dstPort: 49160 }, 100)).toBe('Permit');
    });
  });
});
