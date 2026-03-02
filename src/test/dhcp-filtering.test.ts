import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('DHCP Filtering, Applied ACLs', () => {
  describe('permit all DHCP to server port', () => {
    it('permits UDP DHCP to port 67', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
    });
  });

  describe('permit DHCP to specific server', () => {
    it('permits DHCP to known DHCP server', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
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
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.2', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });
  });

  describe('DHCP client port 68', () => {
    it('permits DHCP client port 68', () => {
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.2.16.1', dstIp: '10.1.4.1', srcPort: 67, dstPort: 68 }, 100)).toBe('Permit');
    });
  });

  describe('DHCP with IP helper on inbound interface', () => {
    it('matches DHCP before helper function changes addresses', () => {
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

    it('matches DHCP after helper function changes addresses', () => {
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
  });

  describe('DHCP outbound ACL bypass', () => {
    it('DHCP packets bypass outbound ACL on helper router', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 67 },
      });

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.254', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });
  });

  describe('DHCP with multiple servers', () => {
    it('permits DHCP to multiple known servers', () => {
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
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.16.2',
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

      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.1', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.2', srcPort: 68, dstPort: 67 }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'udp', srcIp: '10.1.4.1', dstIp: '10.2.16.3', srcPort: 68, dstPort: 67 }, 100)).toBe('Deny');
    });
  });
});
