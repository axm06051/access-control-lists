import { IPv4, AceMatch, AccessControlEntry, AccessList, Operation, ReservedRanges } from '../types/acls';

// ─────────────────────────────────────────────────────────────────────────────
// IPv4
// ─────────────────────────────────────────────────────────────────────────────

describe('IPv4', () => {
  describe('constructor', () => {
    it('splits address into octets', () => {
      const ip = new IPv4('192.168.1.0');
      expect(ip.octets).toEqual(['192', '168', '1', '0']);
    });

    it('converts each octet to 8-bit binary string', () => {
      const ip = new IPv4('192.168.1.0');
      expect(ip.binary).toEqual(['11000000', '10101000', '00000001', '00000000']);
    });

    it('zero-pads octets smaller than 128', () => {
      const ip = new IPv4('0.0.0.1');
      expect(ip.binary).toEqual(['00000000', '00000000', '00000000', '00000001']);
    });

    it('handles 255.255.255.255', () => {
      const ip = new IPv4('255.255.255.255');
      expect(ip.binary).toEqual(['11111111', '11111111', '11111111', '11111111']);
    });

    it('handles 0.0.0.0', () => {
      const ip = new IPv4('0.0.0.0');
      expect(ip.binary).toEqual(['00000000', '00000000', '00000000', '00000000']);
    });
  });

  describe('toString()', () => {
    it('returns dotted-decimal', () => {
      expect(new IPv4('10.0.0.1').toString()).toBe('10.0.0.1');
    });
  });

  describe('toBinaryString()', () => {
    it('returns dot-separated binary octets', () => {
      expect(new IPv4('192.168.1.0').toBinaryString()).toBe('11000000.10101000.00000001.00000000');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AceMatch
// ─────────────────────────────────────────────────────────────────────────────

describe('AceMatch', () => {
  const src = new IPv4('192.168.1.1');
  const target = new IPv4('192.168.1.0');
  const wildcard = new IPv4('0.0.0.255');

  it('stores isMatch=true and no exitAt on a match', () => {
    const m = new AceMatch(true, src, target, wildcard);
    expect(m.isMatch).toBe(true);
    expect(m.exitAt).toBeUndefined();
  });

  it('stores isMatch=false and exitAt on a miss', () => {
    const m = new AceMatch(false, src, target, wildcard, [2, 7]);
    expect(m.isMatch).toBe(false);
    expect(m.exitAt).toEqual([2, 7]);
  });

  it('exposes src, target, and wildcard', () => {
    const m = new AceMatch(true, src, target, wildcard);
    expect(m.src).toBe(src);
    expect(m.target).toBe(target);
    expect(m.wildcard).toBe(wildcard);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessControlEntry — assess()
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessControlEntry.assess()', () => {
  // ── /24 wildcard (0.0.0.255) ──────────────────────────────────────────────

  describe('with /24 wildcard 0.0.0.255', () => {
    // target 192.168.1.0  wildcard 0.0.0.255
    // first three octets must match; last octet is free
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');

    it('matches a host inside the subnet', () => {
      expect(ace.assess('192.168.1.1').isMatch).toBe(true);
    });

    it('matches the network address itself', () => {
      expect(ace.assess('192.168.1.0').isMatch).toBe(true);
    });

    it('matches the broadcast address', () => {
      expect(ace.assess('192.168.1.255').isMatch).toBe(true);
    });

    it('misses a host in a different /24', () => {
      expect(ace.assess('192.168.2.1').isMatch).toBe(false);
    });

    it('records exitAt in the third octet (index 2) on a miss', () => {
      const m = ace.assess('192.168.2.99');
      expect(m.isMatch).toBe(false);
      expect(m.exitAt?.[0]).toBe(2); // octet index 2 = third octet
    });

    it('misses a completely different address', () => {
      expect(ace.assess('10.0.0.1').isMatch).toBe(false);
    });
  });

  // ── /16 wildcard (0.0.255.255) ────────────────────────────────────────────

  describe('with /16 wildcard 0.0.255.255', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.0.0', '0.0.255.255');

    it('matches any host in 192.168.x.x', () => {
      expect(ace.assess('192.168.2.99').isMatch).toBe(true);
      expect(ace.assess('192.168.3.10').isMatch).toBe(true);
      expect(ace.assess('192.168.255.255').isMatch).toBe(true);
    });

    it('misses a host in a different /8', () => {
      expect(ace.assess('10.0.0.1').isMatch).toBe(false);
    });
  });

  // ── host wildcard (0.0.0.0) ──────────────────────────────────────────────

  describe('with host wildcard 0.0.0.0', () => {
    const ace = new AccessControlEntry(10, Operation.Deny, '192.168.1.11', '0.0.0.0');

    it('matches only the exact IP', () => {
      expect(ace.assess('192.168.1.11').isMatch).toBe(true);
    });

    it('misses any other address', () => {
      expect(ace.assess('192.168.1.12').isMatch).toBe(false);
      expect(ace.assess('192.168.1.10').isMatch).toBe(false);
    });
  });

  // ── permit-any wildcard (255.255.255.255) ─────────────────────────────────

  describe('with permit-any wildcard 255.255.255.255', () => {
    const ace = new AccessControlEntry(30, Operation.Permit, '0.0.0.0', '255.255.255.255');

    it('matches every address', () => {
      expect(ace.assess('1.2.3.4').isMatch).toBe(true);
      expect(ace.assess('0.0.0.0').isMatch).toBe(true);
      expect(ace.assess('255.255.255.255').isMatch).toBe(true);
    });
  });

  // ── exitAt bit position accuracy ─────────────────────────────────────────

  describe('exitAt bit position', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');

    it('points to the LSB (bit index 7) when only the last bit differs (odd vs even)', () => {
      // 192.168.2.x vs 192.168.1.x: octet 2 is 00000010 vs 00000001
      // scanning i=7→0: first diff at i=7 (LSB)
      const m = ace.assess('192.168.2.99');
      expect(m.exitAt).toEqual([2, 7]);
    });

    it('points to bit index 6 when bits 6 and 7 both differ', () => {
      // 192.168.3.x (00000011) vs 192.168.1.x (00000001): first diff at i=7? No.
      // i=7: '1' vs '1' equal; i=6: '1' vs '0' → exitAt [2,6]
      const m = ace.assess('192.168.3.10');
      expect(m.exitAt).toEqual([2, 6]);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessControlEntry — resolveAction()
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessControlEntry.resolveAction()', () => {
  const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  afterEach(() => consoleSpy.mockClear());
  afterAll(() => consoleSpy.mockRestore());

  it('returns Permit on a matching Permit ACE', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');
    const match = ace.assess('192.168.1.5');
    expect(ace.resolveAction(match)).toBe(Operation.Permit);
  });

  it('returns Deny on a matching Deny ACE', () => {
    const ace = new AccessControlEntry(10, Operation.Deny, '192.168.1.0', '0.0.0.255');
    const match = ace.assess('192.168.1.5');
    expect(ace.resolveAction(match)).toBe(Operation.Deny);
  });

  it('returns Deny on a miss regardless of ACE operation', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');
    const match = ace.assess('10.0.0.1');
    expect(ace.resolveAction(match)).toBe(Operation.Deny);
  });

  it('logs seq + operation name on a match', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');
    const match = ace.assess('192.168.1.1');
    ace.resolveAction(match);
    expect(consoleSpy).toHaveBeenCalledWith(10, 'Permit');
  });

  it('does not log seq on a miss (calls showMiss instead)', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');
    const match = ace.assess('10.0.0.1');
    ace.resolveAction(match);
    // console.log IS called by showMiss, but never with (seq, opName) pattern
    const seqOpCall = consoleSpy.mock.calls.find((c) => c[0] === 10 && c[1] === 'Permit');
    expect(seqOpCall).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessControlEntry — toString()
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessControlEntry.toString()', () => {
  it('formats seq, operation, src IP and wildcard with padding', () => {
    const ace = new AccessControlEntry(10, Operation.Permit, '192.168.1.0', '0.0.0.255');
    const s = ace.toString();
    expect(s).toContain('10');
    expect(s).toContain('Permit');
    expect(s).toContain('192.168.1.0');
    expect(s).toContain('0.0.0.255');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessList — addStandardNumbered / sequence numbering
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessList sequence numbering', () => {
  it('assigns sequence numbers starting at 10, incrementing by 10', () => {
    const acl = new AccessList();
    acl.addStandardNumbered(1, Operation.Deny, '192.168.1.0', '0.0.0.255');
    acl.addStandardNumbered(1, Operation.Permit, '0.0.0.0', '255.255.255.255');
    const out = acl.toString();
    expect(out).toContain('10');
    expect(out).toContain('20');
  });

  it('respects a custom increment', () => {
    const acl = new AccessList();
    acl.setIncrement(5);
    acl.addStandardNumbered(1, Operation.Deny, '192.168.1.0', '0.0.0.255');
    acl.addStandardNumbered(1, Operation.Permit, '0.0.0.0', '255.255.255.255');
    const out = acl.toString();
    expect(out).toContain('5');
    expect(out).toContain('10');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessList — getAclType via toString()
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessList ACL type detection', () => {
  it.each([
    [1, 'Standard'],
    [99, 'Standard'],
    [1300, 'Standard'],
    [1999, 'Standard'],
    [100, 'Extended'],
    [199, 'Extended'],
    [2000, 'Extended'],
    [2699, 'Extended'],
  ])('ACL id %i is labelled %s', (id, expected) => {
    const acl = new AccessList();
    acl.addStandardNumbered(id, Operation.Permit, '0.0.0.0', '255.255.255.255');
    expect(acl.toString()).toContain(`${expected} IP Access List ${id}`);
  });

  it('throws RangeError for an out-of-range ACL id', () => {
    const acl = new AccessList();
    acl.addStandardNumbered(200, Operation.Permit, '0.0.0.0', '255.255.255.255');
    expect(() => acl.toString()).toThrow(RangeError);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AccessList — validate() — book scenarios (Chapter 23)
// ─────────────────────────────────────────────────────────────────────────────

describe('AccessList.validate() — Chapter 23 book scenarios', () => {
  // Suppress console output from resolveAction / showMiss during these tests
  beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
  afterAll(() => jest.restoreAllMocks());

  // ── ACL 1 (Fig 23.7) ────────────────────────────────────────────────────

  describe('ACL 1 — deny 192.168.1.0/24, permit 192.168.0.0/16 (Fig 23.7)', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandardNumbered(1, Operation.Deny, '192.168.1.0', '0.0.0.255');
      acl.addStandardNumbered(1, Operation.Permit, '192.168.0.0', '0.0.255.255');
    });

    it('Pkt1 — engineering host 192.168.1.2 is DENIED', () => {
      expect(acl.validate('192.168.1.2', 1)).toBe('Deny');
    });

    it('Pkt2 — accounting host 192.168.2.99 is PERMITTED', () => {
      expect(acl.validate('192.168.2.99', 1)).toBe('Permit');
    });

    it('Pkt3 — server LAN host 192.168.3.10 is PERMITTED', () => {
      expect(acl.validate('192.168.3.10', 1)).toBe('Permit');
    });

    it('Fig 23.1 — engineering 192.168.1.1 matches deny ACE', () => {
      expect(acl.validate('192.168.1.1', 1)).toBe('Deny');
    });

    it('Fig 23.3 — external 172.16.1.1 is denied by implicit deny', () => {
      expect(acl.validate('172.16.1.1', 1)).toBe('Deny');
    });
  });

  // ── ACL 99 / BLOCK_MARTHA_BOB (Fig 23.8) ────────────────────────────────

  describe('ACL 99 — BLOCK_MARTHA_BOB (Fig 23.8)', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandardNumbered(99, Operation.Deny, '192.168.1.11', '0.0.0.0');
      acl.addStandardNumbered(99, Operation.Deny, '192.168.2.17', '0.0.0.0');
      acl.addStandardNumbered(99, Operation.Permit, '0.0.0.0', '255.255.255.255');
    });

    it('Martha 192.168.1.11 is DENIED by ACE 10', () => {
      expect(acl.validate('192.168.1.11', 99)).toBe('Deny');
    });

    it('Bob 192.168.2.17 is DENIED by ACE 20', () => {
      expect(acl.validate('192.168.2.17', 99)).toBe('Deny');
    });

    it('Other engineering host 192.168.1.2 is PERMITTED by ACE 30', () => {
      expect(acl.validate('192.168.1.2', 99)).toBe('Permit');
    });

    it('Other accounting host 192.168.2.5 is PERMITTED by ACE 30', () => {
      expect(acl.validate('192.168.2.5', 99)).toBe('Permit');
    });
  });

  // ── ACL 10 — Sec 23.3, R2 (protect Server LAN B) ────────────────────────

  describe('ACL 10 — deny accounting/24, permit any (Sec 23.3)', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandardNumbered(10, Operation.Deny, '192.168.2.0', '0.0.0.255');
      acl.addStandardNumbered(10, Operation.Permit, '0.0.0.0', '255.255.255.255');
    });

    it('accounting host 192.168.2.1 is DENIED', () => {
      expect(acl.validate('192.168.2.1', 10)).toBe('Deny');
    });

    it('engineering host 192.168.1.5 is PERMITTED', () => {
      expect(acl.validate('192.168.1.5', 10)).toBe('Permit');
    });
  });

  // ── ACL 11 — BLOCK_ENGINEERING on R1 G0/1 (Sec 23.3) ───────────────────

  describe('ACL 11 — BLOCK_ENGINEERING (Sec 23.3)', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandardNumbered(11, Operation.Deny, '192.168.1.0', '0.0.0.255');
      acl.addStandardNumbered(11, Operation.Permit, '0.0.0.0', '255.255.255.255');
    });

    it('engineering host is DENIED', () => {
      expect(acl.validate('192.168.1.10', 11)).toBe('Deny');
    });

    it('accounting host passes through', () => {
      expect(acl.validate('192.168.2.10', 11)).toBe('Permit');
    });
  });

  // ── ACL 12 — BLOCK_ACCOUNTING on R1 G0/0 (Sec 23.3) ────────────────────

  describe('ACL 12 — BLOCK_ACCOUNTING (Sec 23.3)', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandardNumbered(12, Operation.Deny, '192.168.2.0', '0.0.0.255');
      acl.addStandardNumbered(12, Operation.Permit, '0.0.0.0', '255.255.255.255');
    });

    it('accounting host is DENIED', () => {
      expect(acl.validate('192.168.2.20', 12)).toBe('Deny');
    });

    it('engineering host passes through', () => {
      expect(acl.validate('192.168.1.20', 12)).toBe('Permit');
    });
  });

  // ── First-match semantics ────────────────────────────────────────────────

  describe('first-match semantics', () => {
    it('stops at the first matching ACE and does not evaluate the rest', () => {
      // deny /24 then permit /16 — a /24 host should be denied,
      // not permitted by the broader /16 rule that follows
      const acl = new AccessList();
      acl.addStandardNumbered(1, Operation.Deny, '192.168.1.0', '0.0.0.255');
      acl.addStandardNumbered(1, Operation.Permit, '192.168.0.0', '0.0.255.255');
      expect(acl.validate('192.168.1.99', 1)).toBe('Deny');
    });
  });

  // ── Implicit deny ────────────────────────────────────────────────────────

  describe('implicit deny', () => {
    it('denies a packet that matches no ACE', () => {
      const acl = new AccessList();
      acl.addStandardNumbered(1, Operation.Permit, '192.168.1.0', '0.0.0.255');
      expect(acl.validate('10.0.0.1', 1)).toBe('Deny');
    });

    it('denies any packet when the ACL id does not exist', () => {
      const acl = new AccessList();
      expect(acl.validate('192.168.1.1', 999)).toBe('Deny');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ReservedRanges — boundary checks
// ─────────────────────────────────────────────────────────────────────────────

describe('ReservedRanges', () => {
  it('Standard lower range starts at 1 and ends at 99', () => {
    expect(ReservedRanges.Standard[0]).toEqual({ start: 1, stop: 99 });
  });

  it('Standard upper range starts at 1300 and ends at 1999', () => {
    expect(ReservedRanges.Standard[1]).toEqual({ start: 1300, stop: 1999 });
  });

  it('Extended lower range starts at 100 and ends at 199', () => {
    expect(ReservedRanges.Extended[0]).toEqual({ start: 100, stop: 199 });
  });

  it('Extended upper range starts at 2000 and ends at 2699', () => {
    expect(ReservedRanges.Extended[1]).toEqual({ start: 2000, stop: 2699 });
  });
});
