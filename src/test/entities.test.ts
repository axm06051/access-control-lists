import { StandardACE, ExtendedACE } from '@/domains/acl/entities';
import { Operation } from '@/domains/acl/constants';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('StandardACE. Sequence Number Management', () => {
  it('stores sequence number', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.sequenceNumber).toBe(10);
  });

  it('resequences to new number', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    ace.resequence(50);
    expect(ace.sequenceNumber).toBe(50);
  });

  it('resequences multiple times', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    ace.resequence(50);
    ace.resequence(100);
    expect(ace.sequenceNumber).toBe(100);
  });

  it('resequences to 1', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    ace.resequence(1);
    expect(ace.sequenceNumber).toBe(1);
  });

  it('resequences to large number', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    ace.resequence(2147483647);
    expect(ace.sequenceNumber).toBe(2147483647);
  });
});

describe('StandardACE. Operation Storage', () => {
  it('stores Permit operation', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.operation).toBe(Operation.Permit);
  });

  it('stores Deny operation', () => {
    const ace = new StandardACE(10, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.operation).toBe(Operation.Deny);
  });
});

describe('StandardACE. Kind Property', () => {
  it('has kind property set to Standard', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.kind).toBe('Standard');
  });
});

describe('StandardACE. resolveAction', () => {
  it('returns Permit when Permit ACE matches', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.resolveAction(true)).toBe(Operation.Permit);
  });

  it('returns Deny when Permit ACE does not match', () => {
    const ace = new StandardACE(10, { op: Operation.Permit, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.resolveAction(false)).toBe(Operation.Deny);
  });

  it('returns Deny when Deny ACE matches', () => {
    const ace = new StandardACE(10, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.resolveAction(true)).toBe(Operation.Deny);
  });

  it('returns Deny when Deny ACE does not match', () => {
    const ace = new StandardACE(10, { op: Operation.Deny, srcIp: '192.168.1.0', wildcardMask: '0.0.0.255' });
    expect(ace.resolveAction(false)).toBe(Operation.Deny);
  });
});

describe('ExtendedACE. Sequence Number Management', () => {
  it('stores sequence number', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.sequenceNumber).toBe(20);
  });

  it('resequences to new number', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    ace.resequence(100);
    expect(ace.sequenceNumber).toBe(100);
  });
});

describe('ExtendedACE. Kind Property', () => {
  it('has kind property set to Extended', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.kind).toBe('Extended');
  });
});

describe('ExtendedACE. Protocol Matching', () => {
  it('ip protocol matches tcp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'ip', ...ANY });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(true);
  });

  it('ip protocol matches udp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'ip', ...ANY });
    expect(ace.assess({ protocol: 'udp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(true);
  });

  it('ip protocol matches icmp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'ip', ...ANY });
    expect(ace.assess({ protocol: 'icmp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(true);
  });

  it('tcp protocol rejects udp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.assess({ protocol: 'udp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(false);
  });

  it('udp protocol rejects tcp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'udp', ...ANY });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(false);
  });

  it('icmp protocol rejects tcp', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'icmp', ...ANY });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' })).toBe(false);
  });
});

describe('ExtendedACE. Source Port Matching', () => {
  it('matches source port eq', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      srcPort: { op: 'eq', port: 80 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 80 })).toBe(true);
  });

  it('rejects non-matching source port', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      srcPort: { op: 'eq', port: 80 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 443 })).toBe(false);
  });

  it('matches source port gt', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      srcPort: { op: 'gt', port: 1023 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 1024 })).toBe(true);
  });

  it('matches source port lt', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      srcPort: { op: 'lt', port: 1024 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 1023 })).toBe(true);
  });

  it('matches source port range', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      srcPort: { op: 'range', portA: 1024, portB: 65535 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 50000 })).toBe(true);
  });
});

describe('ExtendedACE. Destination Port Matching', () => {
  it('matches destination port eq', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'eq', port: 443 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 443 })).toBe(true);
  });

  it('rejects non-matching destination port', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'eq', port: 443 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 80 })).toBe(false);
  });

  it('matches destination port neq', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'neq', port: 23 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 80 })).toBe(true);
  });

  it('rejects matching neq port', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'neq', port: 23 },
    });
    expect(ace.assess({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 23 })).toBe(false);
  });
});

describe('ExtendedACE. Complex Combinations', () => {
  it('matches all conditions with AND logic', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '192.168.1.0',
      srcWildcard: '0.0.0.255',
      dstIp: '192.168.3.0',
      dstWildcard: '0.0.0.255',
      srcPort: { op: 'gt', port: 1023 },
      dstPort: { op: 'eq', port: 443 },
    });

    expect(
      ace.assess({
        protocol: 'tcp',
        srcIp: '192.168.1.5',
        dstIp: '192.168.3.10',
        srcPort: 50000,
        dstPort: 443,
      })
    ).toBe(true);
  });

  it('fails if any condition fails', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '192.168.1.0',
      srcWildcard: '0.0.0.255',
      dstIp: '192.168.3.0',
      dstWildcard: '0.0.0.255',
      srcPort: { op: 'gt', port: 1023 },
      dstPort: { op: 'eq', port: 443 },
    });

    expect(
      ace.assess({
        protocol: 'udp',
        srcIp: '192.168.1.5',
        dstIp: '192.168.3.10',
        srcPort: 50000,
        dstPort: 443,
      })
    ).toBe(false);
  });
});

describe('ExtendedACE. toString', () => {
  it('includes sequence number', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.toString()).toContain('20');
  });

  it('includes operation', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.toString()).toContain('Permit');
  });

  it('includes protocol', () => {
    const ace = new ExtendedACE(20, { op: Operation.Permit, protocol: 'tcp', ...ANY });
    expect(ace.toString()).toContain('tcp');
  });

  it('includes source IP', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '192.168.1.0',
      srcWildcard: '0.0.0.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
    });
    expect(ace.toString()).toContain('192.168.1.0');
  });

  it('includes destination IP', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '0.0.0.0',
      srcWildcard: '255.255.255.255',
      dstIp: '192.168.3.0',
      dstWildcard: '0.0.0.255',
    });
    expect(ace.toString()).toContain('192.168.3.0');
  });

  it('includes port information when present', () => {
    const ace = new ExtendedACE(20, {
      op: Operation.Permit,
      protocol: 'tcp',
      ...ANY,
      dstPort: { op: 'eq', port: 443 },
    });
    expect(ace.toString()).toContain('443');
  });
});
