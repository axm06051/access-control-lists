import { AccessList, Operation } from '@/slices/infrastructure';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

const ANY = { srcIp: '0.0.0.0', srcWildcard: '255.255.255.255', dstIp: '0.0.0.0', dstWildcard: '255.255.255.255' };

describe('DNS (Port 53)', () => {
  describe('permit DNS queries from LAN', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(100, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '8.8.8.8',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(100, { op: Operation.Deny, protocol: 'udp', ...ANY, dstPort: { op: 'eq', port: 53 } });
      acl.addExtended(100, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('LAN DNS query to 8.8.8.8 -> PERMIT', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '8.8.8.8', dstPort: 53 }, 100)).toBe(
        'Permit'
      ));
    it('external DNS query to 8.8.8.8 -> DENY', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '10.0.0.1', dstIp: '8.8.8.8', dstPort: 53 }, 100)).toBe('Deny'));
    it('LAN to different DNS server -> DENY (implicit)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '1.1.1.1', dstPort: 53 }, 100)).toBe(
        'Deny'
      ));
  });

  describe('permit DNS responses back to LAN', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(101, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '8.8.8.8',
        srcWildcard: '0.0.0.0',
        dstIp: '192.168.1.0',
        dstWildcard: '0.0.0.255',
        srcPort: { op: 'eq', port: 53 },
      });
      acl.addExtended(101, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('DNS response from 8.8.8.8 srcPort 53 -> PERMIT', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '8.8.8.8', dstIp: '192.168.1.5', srcPort: 53 }, 101)).toBe(
        'Permit'
      ));
    it('DNS response from different port -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '8.8.8.8', dstIp: '192.168.1.5', srcPort: 54 }, 101)).toBe(
        'Permit'
      ));
  });
});

describe('DHCP (Ports 67, 68)', () => {
  describe('permit DHCP from LAN to server', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(102, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '192.168.1.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 67 },
      });
      acl.addExtended(102, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('DHCP discover to server port 67 -> PERMIT', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '0.0.0.0', dstIp: '192.168.1.1', dstPort: 67 }, 102)).toBe(
        'Permit'
      ));
    it('DHCP to port 68 -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '192.168.1.1', dstPort: 68 }, 102)).toBe(
        'Permit'
      ));
  });

  describe('permit DHCP responses back to clients', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(103, {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '192.168.1.1',
        srcWildcard: '0.0.0.0',
        dstIp: '255.255.255.255',
        dstWildcard: '0.0.0.0',
        srcPort: { op: 'eq', port: 67 },
        dstPort: { op: 'eq', port: 68 },
      });
      acl.addExtended(103, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('DHCP offer from server srcPort 67 dstPort 68 -> PERMIT', () =>
      expect(
        acl.validate({ protocol: 'udp', srcIp: '192.168.1.1', dstIp: '255.255.255.255', srcPort: 67, dstPort: 68 }, 103)
      ).toBe('Permit'));
  });
});

describe('ICMP (Internet Control Message Protocol)', () => {
  describe('permit ICMP echo (ping) between subnets', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(104, {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.2.0',
        dstWildcard: '0.0.0.255',
      });
      acl.addExtended(104, { op: Operation.Deny, protocol: 'icmp', ...ANY });
      acl.addExtended(104, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('ICMP from LAN-A to LAN-B -> PERMIT', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '192.168.1.5', dstIp: '192.168.2.10' }, 104)).toBe('Permit'));
    it('ICMP from LAN-B to LAN-A -> DENY', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '192.168.2.5', dstIp: '192.168.1.10' }, 104)).toBe('Deny'));
    it('ICMP from external -> DENY', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '10.0.0.1', dstIp: '192.168.1.5' }, 104)).toBe('Deny'));
  });

  describe('deny ICMP but permit other traffic', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(105, {
        op: Operation.Deny,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      acl.addExtended(105, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('ICMP traffic -> DENY', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '1.1.1.1', dstIp: '2.2.2.2' }, 105)).toBe('Deny'));
    it('TCP traffic -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 80 }, 105)).toBe('Permit'));
    it('UDP traffic -> PERMIT', () =>
      expect(acl.validate({ protocol: 'udp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', dstPort: 53 }, 105)).toBe('Permit'));
  });
});

describe('OSPF (Open Shortest Path First)', () => {
  describe('permit OSPF between routers', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(106, {
        op: Operation.Permit,
        protocol: 'ip',
        srcIp: '192.168.12.0',
        srcWildcard: '0.0.0.255',
        dstIp: '224.0.0.5',
        dstWildcard: '0.0.0.0',
      });
      acl.addExtended(106, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('OSPF from router to multicast 224.0.0.5 -> PERMIT', () =>
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.12.1', dstIp: '224.0.0.5' }, 106)).toBe('Permit'));
    it('OSPF from non-router subnet -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'ip', srcIp: '192.168.1.5', dstIp: '224.0.0.5' }, 106)).toBe('Permit'));
  });
});

describe('SSH/Telnet (Ports 22, 23)', () => {
  describe('permit SSH, deny Telnet to router', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(107, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.1.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 22 },
      });
      acl.addExtended(107, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '192.168.1.1',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 23 },
      });
      acl.addExtended(107, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('SSH from LAN to router -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.1.1', dstPort: 22 }, 107)).toBe(
        'Permit'
      ));
    it('Telnet from LAN to router -> DENY', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.1.1', dstPort: 23 }, 107)).toBe(
        'Deny'
      ));
    it('SSH from external to router -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '10.0.0.1', dstIp: '192.168.1.1', dstPort: 22 }, 107)).toBe(
        'Permit'
      ));
  });

  describe('vty ACL: permit SSH from management subnet only', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addStandard('VTY_SSH', { op: Operation.Permit, srcIp: '192.168.100.0', wildcardMask: '0.0.0.255' });
      acl.addStandard('VTY_SSH', { op: Operation.Deny, srcIp: '0.0.0.0', wildcardMask: '255.255.255.255' });
    });
    it('SSH from management subnet -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.100.5', dstIp: '192.168.1.1', dstPort: 22 }, 'VTY_SSH')).toBe(
        'Permit'
      ));
    it('SSH from other subnet -> DENY', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.1.1', dstPort: 22 }, 'VTY_SSH')).toBe(
        'Deny'
      ));
  });
});

describe('HTTP/HTTPS (Ports 80, 443)', () => {
  describe('permit HTTPS only, deny HTTP', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(108, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 443 },
      });
      acl.addExtended(108, {
        op: Operation.Deny,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 80 },
      });
      acl.addExtended(108, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('HTTPS from LAN -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '8.8.8.8', dstPort: 443 }, 108)).toBe(
        'Permit'
      ));
    it('HTTP from LAN -> DENY', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '8.8.8.8', dstPort: 80 }, 108)).toBe('Deny'));
    it('other traffic from LAN -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '8.8.8.8', dstPort: 25 }, 108)).toBe(
        'Permit'
      ));
  });

  describe('permit HTTP and HTTPS range', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended(109, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'range', portA: 80, portB: 443 },
      });
      acl.addExtended(109, { op: Operation.Permit, protocol: 'ip', ...ANY });
    });
    it('HTTP to web server -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '192.168.3.10', dstPort: 80 }, 109)).toBe(
        'Permit'
      ));
    it('HTTPS to web server -> PERMIT', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '192.168.3.10', dstPort: 443 }, 109)).toBe(
        'Permit'
      ));
    it('port 8080 to web server -> PERMIT (implicit)', () =>
      expect(acl.validate({ protocol: 'tcp', srcIp: '1.1.1.1', dstIp: '192.168.3.10', dstPort: 8080 }, 109)).toBe(
        'Permit'
      ));
  });
});

describe('Complex multi-protocol scenarios', () => {
  describe('comprehensive network ACL', () => {
    const acl = new AccessList();
    beforeAll(() => {
      acl.addExtended('CORP_POLICY', {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '192.168.3.0',
        dstWildcard: '0.0.0.255',
        dstPort: { op: 'range', portA: 80, portB: 443 },
      });
      acl.addExtended('CORP_POLICY', {
        op: Operation.Permit,
        protocol: 'udp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '8.8.8.8',
        dstWildcard: '0.0.0.0',
        dstPort: { op: 'eq', port: 53 },
      });
      acl.addExtended('CORP_POLICY', {
        op: Operation.Permit,
        protocol: 'icmp',
        srcIp: '192.168.1.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
      });
      acl.addExtended('CORP_POLICY', { op: Operation.Deny, protocol: 'ip', ...ANY });
    });
    it('engineering web traffic -> PERMIT', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '192.168.3.10', dstPort: 443 }, 'CORP_POLICY')
      ).toBe('Permit'));
    it('engineering DNS query -> PERMIT', () =>
      expect(
        acl.validate({ protocol: 'udp', srcIp: '192.168.1.5', dstIp: '8.8.8.8', dstPort: 53 }, 'CORP_POLICY')
      ).toBe('Permit'));
    it('engineering ICMP -> PERMIT', () =>
      expect(acl.validate({ protocol: 'icmp', srcIp: '192.168.1.5', dstIp: '1.1.1.1' }, 'CORP_POLICY')).toBe('Permit'));
    it('accounting web traffic -> DENY', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.2.5', dstIp: '192.168.3.10', dstPort: 443 }, 'CORP_POLICY')
      ).toBe('Deny'));
    it('engineering SSH to external -> DENY', () =>
      expect(
        acl.validate({ protocol: 'tcp', srcIp: '192.168.1.5', dstIp: '10.0.0.1', dstPort: 22 }, 'CORP_POLICY')
      ).toBe('Deny'));
  });
});
