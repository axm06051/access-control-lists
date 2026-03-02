type NumberedACL = 'Standard' | 'Extended';
type AclRange = { start: number; stop: number };

export enum Operation {
  Permit = 1,
  Deny = 0,
}

export const ReservedRanges = {
  Standard: [
    { start: 1, stop: 99 },
    { start: 1300, stop: 1999 },
  ],
  Extended: [
    { start: 100, stop: 199 },
    { start: 2000, stop: 2699 },
  ],
} satisfies Record<NumberedACL, AclRange[]>;

class Ansi {
  static readonly RED = '\x1b[31m';
  static readonly RESET = '\x1b[0m';

  static red = (s: string) => `${Ansi.RED}${s}${Ansi.RESET}`;
}

export class IPv4 {
  /** e.g. ['192','168','1','0'] */
  readonly octets: readonly string[];

  /** e.g. ['11000000','10101000','00000001','00000000'] */
  readonly binary: readonly string[];

  constructor(address: string) {
    this.octets = address.split('.');
    this.binary = this.octets.map((o) => parseInt(o, 10).toString(2).padStart(8, '0'));
  }

  toString(): string {
    return this.octets.join('.');
  }

  toBinaryString(): string {
    return this.binary.join('.');
  }
}

export class AceMatch {
  readonly isMatch: boolean;
  /**
   * [octetIndex, bitIndex] of the first mismatching must-match bit.
   * bitIndex IS the string index (0 = MSB/leftmost, 7 = LSB/rightmost).
   * undefined when isMatch === true.
   */
  readonly exitAt: readonly [number, number] | undefined;
  readonly src: IPv4;
  readonly target: IPv4;
  readonly wildcard: IPv4;

  constructor(isMatch: boolean, src: IPv4, target: IPv4, wildcard: IPv4, exitAt?: readonly [number, number]) {
    this.isMatch = isMatch;
    this.src = src;
    this.target = target;
    this.wildcard = wildcard;
    this.exitAt = exitAt;
  }
}

const PAD = {
  index: 4,
  operation: 7,
  ipv4: 15,
  wildcard: 15,
} as const;

export class AccessControlEntry {
  readonly #seq: number;
  readonly #ipAddr: IPv4;
  readonly #wildcard: IPv4;
  readonly #op: Operation;

  constructor(sequenceNumber: number, operation: Operation, srcIp: string, wildcardMask: string) {
    this.#seq = sequenceNumber;
    this.#ipAddr = new IPv4(srcIp);
    this.#wildcard = new IPv4(wildcardMask);
    this.#op = operation;
  }

  get sequenceNumber(): number {
    return this.#seq;
  }
  get operation(): Operation {
    return this.#op;
  }

  assess(srcIpAddress: string): AceMatch {
    const src = new IPv4(srcIpAddress);
    const target = this.#ipAddr;
    const wildcard = this.#wildcard;

    const lastOctet = 3;
    const msb = 0; // left, most significant bit
    const lsb = 7; // right, least significant bit
    for (let o = lastOctet; o > -1; o--) {
      for (let i = lsb; msb <= i; i--) {
        const mustMatch = wildcard.binary[o][i] === '0';
        const isMatch = src.binary[o][i] === target.binary[o][i];

        if (mustMatch && !isMatch) {
          return new AceMatch(false, src, target, wildcard, [o, i]);
        }
      }
    }
    return new AceMatch(true, src, target, wildcard);
  }

  /**
   * Logs the sequence number + operation on a match, or the bit-level
   * diff table on a miss, then returns the resolved Operation.
   */
  resolveAction(match: AceMatch): Operation {
    if (match.isMatch) {
      console.log(this.#seq, Operation[this.#op]);
      return this.#op;
    }
    this.showMiss(match);
    return Operation.Deny;
  }

  showMiss(match: AceMatch): void {
    const [octetIdx, bitIdx] = match.exitAt ?? [0, 0];

    const row = (label: string, ip: IPv4): string => {
      const dec = ip.toString().padEnd(PAD.ipv4);
      const bin = ip.binary
        .map((oct, i) => {
          if (i !== octetIdx) return oct;
          const before = oct.slice(0, bitIdx);
          const bit = Ansi.red(oct[bitIdx]);
          const after = oct.slice(bitIdx + 1);
          return before + bit + after;
        })
        .join('.');
      return `  ${label} : ${dec}  ${bin}`;
    };

    // Left padding = bitIdx (bitIdx IS string position from left).
    const decColWidth = PAD.ipv4 + 2;
    const arrow = match.target.binary
      .map((_, i) => (i === octetIdx ? ' '.repeat(bitIdx) + '^' + ' '.repeat(7 - bitIdx) : ' '.repeat(8)))
      .join('.');

    console.log(
      [
        '',
        row('src    ', match.src),
        row('target ', match.target),
        `   ${''.padEnd(7)}  ${''.padEnd(decColWidth)}${arrow}`,
        row('wild   ', match.wildcard),
        '',
      ].join('\n')
    );
  }

  toString(): string {
    const seq = this.#seq.toString().padEnd(PAD.index);
    const op = Operation[this.#op].padEnd(PAD.operation);
    const src = this.#ipAddr.toString().padEnd(PAD.ipv4);
    const wildcard = this.#wildcard.toString().padEnd(PAD.wildcard);
    return `${seq} ${op} ${src} ${wildcard}`;
  }
}

export class AccessList {
  #incrementBy: number;
  #entries: Map<number, AccessControlEntry[]>;

  constructor() {
    this.#incrementBy = 10;
    this.#entries = new Map();
  }

  setIncrement(n: number): void {
    this.#incrementBy = n;
  }

  addStandardNumbered(id: number, op: Operation, src: string, mask: string): void {
    const rules = this.#entries.get(id) ?? [];
    const prev = rules.at(-1)?.sequenceNumber ?? 0;
    const seq = prev + this.#incrementBy;
    this.#entries.set(id, [...rules, new AccessControlEntry(seq, op, src, mask)]);
  }

  validate(srcIp: string, aclId: number): string {
    const rules = this.#entries.get(aclId) ?? [];

    for (const ace of rules) {
      const match = ace.assess(srcIp);
      const action = ace.resolveAction(match);

      if (match.isMatch) return Operation[action];
    }

    return Operation[Operation.Deny]; // implicit deny
  }

  toString(listMarker = ' '): string {
    let out = '';
    for (const [key, rules] of this.#entries) {
      out += `${this.#aclType(key)} IP Access List ${key}\n`;
      for (const ace of rules) out += `${listMarker}${ace.toString()}\n`;
    }
    return out;
  }

  #aclType(key: number): NumberedACL {
    const inRange = (n: number, { start, stop }: AclRange) => ((n - start) | (stop - n)) >= 0;

    for (const [type, ranges] of Object.entries(ReservedRanges)) {
      if (ranges.some((r) => inRange(key, r))) return type as NumberedACL;
    }
    throw new RangeError(`ACL key ${key} is not within any reserved range`);
  }
}

export default { AccessList, ReservedRanges };
