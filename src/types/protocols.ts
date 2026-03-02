export type L3Protocol = 'ip' | 'tcp' | 'udp' | 'icmp' | 'ospf';

type Application = {
  name: string;
  port: number;
  description?: string;
};

type OctetBits = string & { readonly _brand: 'OctetBits' };

function toBits(octet: string): OctetBits {
  return parseInt(octet, 10).toString(2).padStart(8, '0') as OctetBits;
}

function parseOctets(address: string): [string, string, string, string] {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((p) => p === '' || isNaN(parseInt(p, 10)))) {
    throw new RangeError(`Invalid IPv4 address: "${address}"`);
  }
  const [a, b, c, d] = parts;
  return [a!, b!, c!, d!];
}

export class IPv4 {
  readonly octets: readonly [string, string, string, string];
  readonly binary: readonly [OctetBits, OctetBits, OctetBits, OctetBits];

  constructor(address: string) {
    const [a, b, c, d] = parseOctets(address);
    this.octets = [a, b, c, d];
    this.binary = [toBits(a), toBits(b), toBits(c), toBits(d)];
  }

  toString(): string {
    return this.octets.join('.');
  }

  toBinaryString(): string {
    return this.binary.join('.');
  }
}

export type Packet = {
  protocol: L3Protocol;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
};

type PortRange = { start: number; stop: number };
type PortType = 'System' | 'User' | 'Ephemeral';

enum L4Protocol {
  TCP = 'Transmission Control Protocol',
  UDP = 'User Datagram Protocol',
}

abstract class Protocol {
  #apps: Set<Application>;
  readonly #name: L4Protocol;

  constructor(protocolName: L4Protocol) {
    this.#apps = new Set();
    this.#name = protocolName;
  }

  add(app: Application): void {
    this.#apps = new Set([...this.#apps, app]);
  }

  remove(app: Application): void {
    this.#apps.delete(app);
  }

  resolvePort(keyword: string): number | null {
    const lower = keyword.toLowerCase();
    for (const app of this.#apps) {
      if (app.name.toLowerCase() === lower) return app.port;
    }
    const n = parseInt(keyword, 10);
    return isNaN(n) ? null : n;
  }

  portMap(): ReadonlyMap<string, number> {
    const map = new Map<string, number>();
    for (const app of this.#apps) {
      if (!map.has(app.name.toLowerCase())) {
        map.set(app.name.toLowerCase(), app.port);
      }
    }
    return map;
  }

  toString(): string {
    return this.#name;
  }
}

class TCP extends Protocol {
  constructor() {
    super(L4Protocol.TCP);
  }
}

class UDP extends Protocol {
  constructor() {
    super(L4Protocol.UDP);
  }
}

const tcp = new TCP();
tcp.add({ name: 'FTP', port: 20, description: 'File Transfer Protocol Data' });
tcp.add({ name: 'FTP', port: 21, description: 'File Transfer Protocol Control' });
tcp.add({ name: 'SSH', port: 22, description: 'Secure Shell' });
tcp.add({ name: 'Telnet', port: 23 });
tcp.add({ name: 'SMTP', port: 25, description: 'Simple Mail Transfer Protocol' });
tcp.add({ name: 'DNS', port: 53, description: 'Domain Name System' });
tcp.add({ name: 'HTTP', port: 80, description: 'Hypertext Transfer Protocol' });
tcp.add({ name: 'POP3', port: 110, description: 'Post Office Protocol version 3' });
tcp.add({ name: 'IMAP', port: 143, description: 'Internet Message Access Protocol' });
tcp.add({ name: 'HTTPS', port: 443, description: 'Hypertext Transfer Protocol Secure' });

const udp = new UDP();
udp.add({ name: 'DNS', port: 53, description: 'Domain Name System' });
udp.add({ name: 'DHCP', port: 67, description: 'Dynamic Host Configuration Protocol Server' });
udp.add({ name: 'DHCP', port: 68, description: 'Dynamic Host Configuration Protocol Client' });
udp.add({ name: 'TFTP', port: 69, description: 'Trivial File Transfer Protocol' });
udp.add({ name: 'NTP', port: 123, description: 'Network Time Protocol' });
udp.add({ name: 'SNMP', port: 161, description: 'Simple Network Management Protocol Agent' });
udp.add({ name: 'SNMP', port: 162, description: 'Simple Network Management Protocol Manager' });
udp.add({ name: 'Syslog', port: 514 });

/**
 * IANA port type ranges (RFC 6335).
 *   System    (well-known): 0–1023
 *   User      (registered): 1024–49151
 *   Ephemeral (dynamic, private): 49152–65535
 */
function getPortType(port: number): PortType {
  const PORT_RANGES = {
    System: { start: 0b00000000_00000000, stop: 0b00000011_11111111 },
    User: { start: 0b00000100_00000000, stop: 0b10111111_11111111 },
    Ephemeral: { start: 0b11000000_00000000, stop: 0b11111111_11111111 },
  } satisfies Record<PortType, PortRange>;

  const isInRange = (port: number, { start, stop }: PortRange): boolean => ((port - start) | (stop - port)) >= 0;

  for (const [type, range] of Object.entries(PORT_RANGES)) {
    if (isInRange(port, range)) return type as PortType;
  }

  throw new RangeError(`Port ${port} is outside the valid 16-bit range [0x0000, 0xFFFF]`);
}

export const protocols = {
  tcp,
  udp,
  getPortType,
};
