import { AccessList } from '@/domains/acl/services';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('ICMP Filtering', () => {
  describe('permit all ICMP', () => {
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

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '192.168.1.1', dstIp: '172.16.0.1' }, 100)).toBe('Permit');
    });
  });

  describe('permit ICMP within private network only', () => {
    it('permits ICMP between private addresses', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.100.100.1', dstIp: '10.200.200.1' }, 100)).toBe('Permit');
    });

    it('denies ICMP to external addresses', () => {
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

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '8.8.8.8' }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'icmp', srcIp: '8.8.8.8', dstIp: '10.1.4.1' }, 100)).toBe('Deny');
    });
  });

  describe('permit ICMP Echo and Echo Reply only', () => {
    it('permits ICMP Echo Request', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
    });

    it('permits ICMP Echo Reply', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.2.2.1', dstIp: '10.1.4.1' }, 100)).toBe('Permit');
    });

    it('denies other ICMP types', () => {
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

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
    });
  });

  describe('ICMP Time Exceeded for traceroute', () => {
    it('permits ICMP for traceroute functionality', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.255.255.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
    });
  });

  describe('ICMP filtering by source and destination', () => {
    it('permits ICMP from specific subnet', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '10.1.4.0',
        srcWildcard: '0.0.0.255',
        dstIp: '10.0.0.0',
        dstWildcard: '0.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.100', dstIp: '10.2.2.1' }, 100)).toBe('Permit');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.5.100', dstIp: '10.2.2.1' }, 100)).toBe('Deny');
    });

    it('denies ICMP to specific subnet', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '10.2.32.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });

      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.32.1' }, 100)).toBe('Deny');
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.1.4.1', dstIp: '10.2.16.1' }, 100)).toBe('Permit');
    });
  });
});
