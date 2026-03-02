type Application = {
  name: string;
  port: number;
  description?: string;
};

type PortRange = { start: number; stop: number };
type PortType = 'System' | 'User' | 'Ephemeral';

enum L4Protocol {
  TCP = 'Transmission Control Protocol',
  UDP = 'User Datagram Protool',
}

abstract class Protocol {
  #apps: Set<Application>;
  #name: L4Protocol;

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

  toString(): string {
    return `${this.#name}`;
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

function getPortType(port: number): PortType {
  const PORT_RANGES = {
    System: { start: 0b00000000_00000000, stop: 0b00000011_11111111 },
    User: { start: 0b00000100_00000000, stop: 0b10111111_11111111 },
    Ephemeral: { start: 0b11000000_00000000, stop: 0b11111111_11111111 },
  } satisfies Record<PortType, PortRange>;

  const isInRange = (port: number, { start, stop }: PortRange): boolean => {
    return ((port - start) | (stop - port)) >= 0;
  };

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
