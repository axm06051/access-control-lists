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
