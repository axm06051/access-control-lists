import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('OSPF Filtering', () => {
  describe('permit all OSPF messages', () => {
    it('permits all OSPF packets', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });
  });

  describe('permit OSPF from known neighbors', () => {
    it('permits OSPF from specific neighbor', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies OSPF from unknown neighbors', () => {
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

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.3', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });
  });

  describe('OSPF Hello packets', () => {
    it('permits OSPF Hello to multicast address', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '224.0.0.5',
        dstWildcard: '0.0.0.0',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('permits OSPF Hello from router IP', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.1',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });
  });

  describe('OSPF on inbound interface', () => {
    it('permits OSPF on inbound interface from neighbor', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.12.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies OSPF from non-neighbor', () => {
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

      expect(acl.validate({ protocol: 'ospf', srcIp: '192.168.1.1', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });
  });

  describe('OSPF bypass for router-generated packets', () => {
    it('router-generated OSPF bypasses outbound ACL by default', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'ospf',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.1', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });
  });

  describe('OSPF with multiple neighbors', () => {
    it('permits OSPF from multiple known neighbors', () => {
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
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.13.2',
        srcWildcard: '0.0.0.0',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.12.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.13.2', dstIp: '224.0.0.5' }, 100)).toBe('Permit');
    });

    it('denies OSPF from unknown neighbor', () => {
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
        op: Operation.Permit,
        protocol: 'ospf',
        srcIp: '10.1.13.2',
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

      expect(acl.validate({ protocol: 'ospf', srcIp: '10.1.14.2', dstIp: '224.0.0.5' }, 100)).toBe('Deny');
    });
  });
});
