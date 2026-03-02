import { StandardACE, ExtendedACE, AccessList } from '../domains/acl/index';
import { Operation, ReservedRanges, type L3Protocol, type Packet } from '@/domains/acl';
import { IPv4 } from '@/domains/shared';
import { PortMatcher, WildcardMatcher, inferKindFromNumber } from '@/domains/shared';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const sp = (srcIp: string): Packet => ({ protocol: 'ip', srcIp, dstIp: '0.0.0.0' });
const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('IPv4', () => {
  it('parses octets', () => expect(new IPv4('192.168.1.0').octets).toEqual(['192', '168', '1', '0']));
  it('converts to 8-bit binary', () =>
    expect(new IPv4('192.168.1.0').binary).toEqual(['11000000', '10101000', '00000001', '00000000']));
  it('zero-pads small octets', () =>
    expect(new IPv4('0.0.0.1').binary).toEqual(['00000000', '00000000', '00000000', '00000001']));
  it('handles 255.255.255.255', () =>
    expect(new IPv4('255.255.255.255').binary).toEqual(['11111111', '11111111', '11111111', '11111111']));
  it('toString() returns decimal', () => expect(new IPv4('10.0.0.1').toString()).toBe('10.0.0.1'));
  it('toBinaryString() dot-separated', () =>
    expect(new IPv4('192.168.1.0').toBinaryString()).toBe('11000000.10101000.00000001.00000000'));
});

describe('PortMatcher', () => {
  it('eq: matches exactly', () => expect(new PortMatcher({ op: 'eq', port: 80 }).matches(80)).toBe(true));
  it('eq: rejects adjacent', () => expect(new PortMatcher({ op: 'eq', port: 80 }).matches(81)).toBe(false));
  it('gt: matches strictly above', () => expect(new PortMatcher({ op: 'gt', port: 1023 }).matches(1024)).toBe(true));
  it('gt: rejects equal value', () => expect(new PortMatcher({ op: 'gt', port: 1023 }).matches(1023)).toBe(false));
  it('lt: matches strictly below', () => expect(new PortMatcher({ op: 'lt', port: 1024 }).matches(1023)).toBe(true));
  it('lt: rejects equal value', () => expect(new PortMatcher({ op: 'lt', port: 1024 }).matches(1024)).toBe(false));
  it('neq: matches anything except', () => expect(new PortMatcher({ op: 'neq', port: 23 }).matches(80)).toBe(true));
  it('neq: rejects the specified port', () => expect(new PortMatcher({ op: 'neq', port: 23 }).matches(23)).toBe(false));
  it('range: matches lower boundary', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).matches(80)).toBe(true));
  it('range: matches upper boundary', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).matches(100)).toBe(true));
  it('range: matches interior', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).matches(90)).toBe(true));
  it('range: rejects below', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).matches(79)).toBe(false));
  it('range: rejects above', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).matches(101)).toBe(false));
  it('toString non-range', () => expect(new PortMatcher({ op: 'eq', port: 443 }).toString()).toBe('eq 443'));
  it('toString range', () =>
    expect(new PortMatcher({ op: 'range', portA: 80, portB: 100 }).toString()).toBe('range 80 100'));
});

describe('WildcardMatcher', () => {
  describe('/24 wildcard (0.0.0.255)', () => {
    const m = new WildcardMatcher('192.168.1.0', '0.0.0.255');
    it('matches host inside subnet', () => expect(m.match('192.168.1.5').isMatch).toBe(true));
    it('matches network address', () => expect(m.match('192.168.1.0').isMatch).toBe(true));
    it('matches broadcast', () => expect(m.match('192.168.1.255').isMatch).toBe(true));
    it('misses different /24', () => expect(m.match('192.168.2.1').isMatch).toBe(false));
    it('records exitAt in octet 2', () => expect(m.match('192.168.2.99').exitAt?.[0]).toBe(2));
    it('exitAt bit 7 for octet diff LSB', () => expect(m.match('192.168.2.99').exitAt).toEqual([2, 7]));
    it('exitAt bit 6 for next diff', () => expect(m.match('192.168.3.10').exitAt).toEqual([2, 6]));
  });

  describe('/16 wildcard (0.0.255.255)', () => {
    const m = new WildcardMatcher('192.168.0.0', '0.0.255.255');
    it('matches any 192.168.x.x', () => expect(m.match('192.168.99.1').isMatch).toBe(true));
    it('misses different /8', () => expect(m.match('10.0.0.1').isMatch).toBe(false));
  });

  describe('host wildcard (0.0.0.0)', () => {
    const m = new WildcardMatcher('192.168.1.11', '0.0.0.0');
    it('matches exact IP', () => expect(m.match('192.168.1.11').isMatch).toBe(true));
    it('misses adjacent IP', () => expect(m.match('192.168.1.12').isMatch).toBe(false));
  });

  describe('permit-any wildcard (255.255.255.255)', () => {
    const m = new WildcardMatcher('0.0.0.0', '255.255.255.255');
    it.each(['0.0.0.0', '1.2.3.4', '255.255.255.255'])('matches %s', (ip) => expect(m.match(ip).isMatch).toBe(true));
  });
});

describe('StandardACE', () => {
  const makeAce = (op: Operation) => new StandardACE(10, { op, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });

  it('kind is Standard', () =>
    expect(new StandardACE(10, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' }).kind).toBe(
      'Standard'
    ));

  it('assess() matches inside subnet', () => expect(makeAce(Operation.Permit).assess(sp('192.168.1.5'))).toBe(true));
  it('assess() misses outside subnet', () => expect(makeAce(Operation.Permit).assess(sp('192.168.2.1'))).toBe(false));

  it('resolveAction() Permit on match', () =>
    expect(makeAce(Operation.Permit).resolveAction(true)).toBe(Operation.Permit));
  it('resolveAction() Deny on miss', () => expect(makeAce(Operation.Permit).resolveAction(false)).toBe(Operation.Deny));
  it('resolveAction() Deny ACE + match', () =>
    expect(makeAce(Operation.Deny).resolveAction(true)).toBe(Operation.Deny));

  it('toString() contains key fields', () => {
    const s = makeAce(Operation.Permit).toString();
    expect(s).toContain('10');
    expect(s).toContain('Permit');
    expect(s).toContain('192.168.1.0');
    expect(s).toContain('0.0.0.255');
  });
});

describe('ExtendedACE', () => {
  const anyAny = { srcIp: '10.0.0.1', dstIp: '10.0.0.2' };

  const makeAce = (protocol: L3Protocol) => new ExtendedACE(10, { op: Operation.Permit, protocol, ...ANY });

  it('kind is Extended', () => expect(makeAce('ip').kind).toBe('Extended'));

  describe('protocol matching', () => {
    it('"ip" matches tcp', () => expect(makeAce('ip').assess({ ...anyAny, protocol: 'tcp' })).toBe(true));
    it('"ip" matches udp', () => expect(makeAce('ip').assess({ ...anyAny, protocol: 'udp' })).toBe(true));
    it('"ip" matches icmp', () => expect(makeAce('ip').assess({ ...anyAny, protocol: 'icmp' })).toBe(true));
    it('"tcp" rejects udp', () => expect(makeAce('tcp').assess({ ...anyAny, protocol: 'udp' })).toBe(false));
    it('"udp" rejects tcp', () => expect(makeAce('udp').assess({ ...anyAny, protocol: 'tcp' })).toBe(false));
    it('"icmp" rejects tcp', () => expect(makeAce('icmp').assess({ ...anyAny, protocol: 'tcp' })).toBe(false));
  });

  describe('src / dst IP matching', () => {
    it('misses wrong src IP', () => {
      const ace = new ExtendedACE(10, {
        op: Operation.Deny,
        protocol: 'ip',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      expect(ace.assess({ protocol: 'ip', srcIp: '10.0.0.1', dstIp: '1.1.1.1' })).toBe(false);
    });
    it('misses wrong dst IP', () => {
      const ace = new ExtendedACE(10, {
        op: Operation.Deny,
        protocol: 'ip',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
      });
      expect(ace.assess({ protocol: 'ip', srcIp: '10.0.0.1', dstIp: '10.0.0.2' })).toBe(false);
    });
    it('matches when both match', () => {
      const ace = new ExtendedACE(10, {
        op: Operation.Permit,
        protocol: 'ip',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
      });
      expect(ace.assess({ protocol: 'ip', srcIp: '192.168.1.5', dstIp: '192.168.3.10' })).toBe(true);
    });
  });

  describe('destination port (eq 443)', () => {
    const ace = new ExtendedACE(10, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'eq', port: 443 },
    });
    it('matches dstPort 443', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 443 })).toBe(true));
    it('misses dstPort 80', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 80 })).toBe(false));
    it('misses absent dstPort', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(false));
  });

  describe('source port (gt 50000)', () => {
    const ace = new ExtendedACE(10, {
      op: Operation.Deny,
      protocol: 'udp',
      ...ANY,
      srcPort: { op: 'gt', port: 50000 },
    });
    it('matches srcPort > 50000', () =>
      expect(ace.assess({ protocol: 'udp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 60000 })).toBe(true));
    it('misses srcPort == 50000', () =>
      expect(ace.assess({ protocol: 'udp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 50000 })).toBe(false));
  });

  describe('AND logic', () => {
    const ace = new ExtendedACE(10, {
      op: Operation.Deny,
      protocol: 'tcp',
      srcIp: '192.168.1.0',
      srcWildcard: '0.0.0.255',
      dstIp: '192.168.3.0',
      dstWildcard: '0.0.0.255',
      dstPort: { op: 'eq', port: 80 },
    });
    it('matches when all conditions met', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 80 })).toBe(true));
    it('misses with wrong protocol', () =>
      expect(ace.assess({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 80 })).toBe(false));
    it('misses with wrong src IP', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '192.168.2.5', dstIp: '192.168.3.10', dstPort: 80 })).toBe(false));
    it('misses with wrong dst IP', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.4.10', dstPort: 80 })).toBe(false));
    it('misses with wrong dst port', () =>
      expect(ace.assess({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 443 })).toBe(false));
  });
});

describe('inferKindFromNumber', () => {
  it.each([1, 50, 99, 1300, 1999])('%i -> Standard', (n) => expect(inferKindFromNumber(n)).toBe('Standard'));
  it.each([100, 150, 199, 2000, 2699])('%i -> Extended', (n) => expect(inferKindFromNumber(n)).toBe('Extended'));
  it('throws for 200 (gap)', () => expect(() => inferKindFromNumber(200)).toThrow(RangeError));
  it('throws for 0', () => expect(() => inferKindFromNumber(0)).toThrow(RangeError));
});

describe('AccessList. Standard Numbered', () => {
  describe('ACL 1. deny engineering, permit /16', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '192.168.0.0', wildcardMask: '0.0.255.255' });
    });
    it('engineering 192.168.1.2 -> DENY', () => expect(acl.validate(sp('192.168.1.2'), 1)).toBe('Deny'));
    it('accounting 192.168.2.99 -> PERMIT', () => expect(acl.validate(sp('192.168.2.99'), 1)).toBe('Permit'));
    it('server 192.168.3.10 -> PERMIT', () => expect(acl.validate(sp('192.168.3.10'), 1)).toBe('Permit'));
    it('external 172.16.1.1 -> implicit DENY', () => expect(acl.validate(sp('172.16.1.1'), 1)).toBe('Deny'));
    it('first-match: 192.168.1.99 -> DENY not PERMIT', () => expect(acl.validate(sp('192.168.1.99'), 1)).toBe('Deny'));
  });

  describe('sequence numbering & increment', () => {
    it('auto-assigns 10, 20…', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      expect(acl.toString()).toContain('10');
      expect(acl.toString()).toContain('20');
    });
    it('respects setIncrement(5)', () => {
      const acl = new AccessList();
      acl.setIncrement(5);
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      expect(acl.toString()).toContain('5 ');
      expect(acl.toString()).toContain('10 ');
    });
  });

  describe('deleteAce and deleteAcl', () => {
    it('deleteAce removes the matching sequence', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      expect(acl.deleteAce(1, 10)).toBe(true);
      expect(acl.validate(sp('192.168.1.5'), 1)).toBe('Permit');
    });
    it('deleteAcl removes the entire list', () => {
      const acl = new AccessList();
      acl.addStandard(1, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      expect(acl.deleteAcl(1)).toBe(true);
      expect(acl.validate(sp('1.2.3.4'), 1)).toBe('Deny');
    });
  });

  describe('implicit deny', () => {
    it('no matching rule -> Deny', () => expect(new AccessList().validate(sp('1.2.3.4'), 999)).toBe('Deny'));
  });

  describe('toString() labels ACL correctly', () => {
    it.each([
      [1, 'Standard IP Access List 1'],
      [99, 'Standard IP Access List 99'],
      [1300, 'Standard IP Access List 1300'],
    ])('id %i -> %s', (id, expected) => {
      const acl = new AccessList();
      acl.addStandard(id, { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      expect(acl.toString()).toContain(expected);
    });

    it.each([
      [100, 'Extended IP Access List 100'],
      [2000, 'Extended IP Access List 2000'],
    ])('id %i -> %s', (id, expected) => {
      const acl = new AccessList();
      acl.addExtended(id, { op: Operation.Permit, protocol: 'ip', ...ANY });
      expect(acl.toString()).toContain(expected);
    });
  });
});

describe('AccessList. Standard Named', () => {
  describe('BLOCK_MARTHA_BOB', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Deny, srcIp: '192.168.1.11', wildcardMask: '0.0.0.0' });
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Deny, srcIp: '192.168.2.17', wildcardMask: '0.0.0.0' });
      acl.addStandard('BLOCK_MARTHA_BOB', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
    });
    it('Martha -> DENY', () => expect(acl.validate(sp('192.168.1.11'), 'BLOCK_MARTHA_BOB')).toBe('Deny'));
    it('Bob -> DENY', () => expect(acl.validate(sp('192.168.2.17'), 'BLOCK_MARTHA_BOB')).toBe('Deny'));
    it('other -> PERMIT (ACE30)', () => expect(acl.validate(sp('192.168.1.5'), 'BLOCK_MARTHA_BOB')).toBe('Permit'));
    it('toString labels named ACL correctly', () =>
      expect(acl.toString()).toContain('Standard IP access list BLOCK_MARTHA_BOB'));
  });

  describe('named ACL accepts string id in validate()', () => {
    it('validate with string id', () => {
      const acl = new AccessList();
      acl.addStandard('MY_ACL', { op: Operation.Permit, srcIp: '10.0.0.0', wildcardMask: '0.0.0.255' });
      expect(acl.validate(sp('10.0.0.5'), 'MY_ACL')).toBe('Permit');
      expect(acl.validate(sp('10.0.1.5'), 'MY_ACL')).toBe('Deny');
    });
  });

  describe('deleteAce on named ACL', () => {
    it('removes specified sequence', () => {
      const acl = new AccessList();
      acl.addStandard('TEST', { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('TEST', { op: Operation.Permit, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
      acl.deleteAce('TEST', 10);
      expect(acl.validate(sp('192.168.1.5'), 'TEST')).toBe('Permit');
    });
  });
});

describe('AccessList. Extended Numbered', () => {
  describe('ACL 100. deny TFTP from accounting', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '192.168.2.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 69 },
      });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('accounting TFTP (69) -> DENY', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.2.5', dstIp: '10.0.0.1', dstPort: 69 }, 100)).toBe(
        'Deny'
      ));
    it('accounting DNS  (53) -> PERMIT', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.2.5', dstIp: '10.0.0.1', dstPort: 53 }, 100)).toBe(
        'Permit'
      ));
    it('engineering TFTP -> PERMIT (diff src)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '10.0.0.1', dstPort: 69 }, 100)).toBe(
        'Permit'
      ));
    it('toString labels Extended numbered', () => expect(acl.toString()).toContain('Extended IP Access List 100'));
  });

  describe('port operators', () => {
    it('gt 50000: denies srcPort > 50000', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '203.0.113.1',
        dstWildcard: '0.0.0.0',
        srcPort: { op: 'gt', port: 50000 },
      });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });
      expect(acl.validate({ protocol: 'udp', srcIp: '1.2.3.4', dstIp: '203.0.113.1', srcPort: 60000 }, 100)).toBe(
        'Deny'
      );
      expect(acl.validate({ protocol: 'udp', srcIp: '1.2.3.4', dstIp: '203.0.113.1', srcPort: 50000 }, 100)).toBe(
        'Permit'
      );
    });

    it('lt 1024 src + gt 1023 dst', () => {
      const acl = new AccessList();
      acl.addExtended(100, {
        op: Operation.Deny,
        protocol: 'tcp',
        ...ANY,
        srcPort: { op: 'lt', port: 1024 },
        dstPort: { op: 'gt', port: 1023 },
      });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '1.2.3.4', dstIp: '5.6.7.8', srcPort: 80, dstPort: 8080 }, 100)
      ).toBe('Deny');
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '1.2.3.4', dstIp: '5.6.7.8', srcPort: 1024, dstPort: 8080 }, 100)
      ).toBe('Permit');
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '1.2.3.4', dstIp: '5.6.7.8', srcPort: 80, dstPort: 1023 }, 100)
      ).toBe('Permit');
    });
  });
});

describe('AccessList. Extended Named', () => {
  describe('TEST2. HTTPS + NTP filtering', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended('TEST2', {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 443 },
      });
      acl.addExtended('TEST2', { op: Operation.Deny, protocol: 'tcp', ...ANY, dstPort: { op: 'eq', port: 443 } });
      acl.addExtended('TEST2', {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '192.168.4.19',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 123 },
      });
      acl.addExtended('TEST2', { op: Operation.Deny, protocol: 'udp', ...ANY, dstPort: { op: 'eq', port: 123 } });
      acl.addExtended('TEST2', { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('engineering HTTPS to LAN-A -> PERMIT (ACE10)', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 443 }, 'TEST2')
      ).toBe('Permit'));
    it('accounting  HTTPS to LAN-A -> DENY   (ACE20)', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.2.5', dstIp: '192.168.3.10', dstPort: 443 }, 'TEST2')
      ).toBe('Deny'));
    it('NTP to SRV2 192.168.4.19 -> PERMIT (ACE30)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '10.0.0.1', dstIp: '192.168.4.19', dstPort: 123 }, 'TEST2')).toBe(
        'Permit'
      ));
    it('NTP to other host -> DENY (ACE40)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '10.0.0.1', dstIp: '8.8.8.8', dstPort: 123 }, 'TEST2')).toBe(
        'Deny'
      ));
    it('HTTP traffic -> PERMIT (ACE50)', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.0.0.1', dstIp: '8.8.8.8', dstPort: 80 }, 'TEST2')).toBe(
        'Permit'
      ));
    it('toString labels Extended named', () => expect(acl.toString()).toContain('Extended IP access list TEST2'));
  });

  describe('ICMP_1. only ICMP between LAN-A and LAN-B', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended('ICMP_1', {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '192.168.3.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.4.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended('ICMP_1', {
        op: Operation.Deny,
        protocol: 'ip',
        srcIp: '192.168.3.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.4.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended('ICMP_1', { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('ICMP LAN-A -> LAN-B -> PERMIT', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '192.168.3.5', dstIp: '192.168.4.10' }, 'ICMP_1')).toBe('Permit'));
    it('TCP  LAN-A -> LAN-B -> DENY', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.3.5', dstIp: '192.168.4.10', dstPort: 80 }, 'ICMP_1')
      ).toBe('Deny'));
    it('TCP  LAN-A -> other -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.3.5', dstIp: '192.168.1.5', dstPort: 80 }, 'ICMP_1')).toBe(
        'Permit'
      ));
  });

  describe('NO_HTTP. deny HTTP from engineering', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended('NO_HTTP', {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended('NO_HTTP', {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.4.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended('NO_HTTP', { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('engineering HTTP to LAN-A -> DENY', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 80 }, 'NO_HTTP')
      ).toBe('Deny'));
    it('engineering HTTP to LAN-B -> DENY', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.4.10', dstPort: 80 }, 'NO_HTTP')
      ).toBe('Deny'));
    it('engineering HTTPS -> PERMIT', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 443 }, 'NO_HTTP')
      ).toBe('Permit'));
    it('accounting HTTP -> PERMIT', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.2.5', dstIp: '192.168.3.10', dstPort: 80 }, 'NO_HTTP')
      ).toBe('Permit'));
  });
});

describe('ReservedRanges', () => {
  it('Standard lower 1 to 99', () => expect(ReservedRanges.Standard[0]).toEqual({ start: 1, stop: 99 }));
  it('Standard upper 1300 to 1999', () => expect(ReservedRanges.Standard[1]).toEqual({ start: 1300, stop: 1999 }));
  it('Extended lower 100 to 199', () => expect(ReservedRanges.Extended[0]).toEqual({ start: 100, stop: 199 }));
  it('Extended upper 2000 to 2699', () => expect(ReservedRanges.Extended[1]).toEqual({ start: 2000, stop: 2699 }));
});
