export type AclRange = { start: number; stop: number };
export type PortOperator = 'eq' | 'gt' | 'lt' | 'neq' | 'range';
export type OctetIndex = 0 | 1 | 2 | 3;
export type BitIndex = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

export enum AclKind {
  Standard = 'Standard',
  Extended = 'Extended',
}

export enum AclIdType {
  Numbered = 'Numbered',
  Named = 'Named',
}

export enum Operation {
  Permit = 1,
  Deny = 0,
}

export const ReservedRanges: Record<AclKind, AclRange[]> = {
  Standard: [
    { start: 1, stop: 99 },
    { start: 1300, stop: 1999 },
  ],
  Extended: [
    { start: 100, stop: 199 },
    { start: 2000, stop: 2699 },
  ],
} as const;

export class Ansi {
  static readonly RED = '\x1b[31m';
  static readonly GREEN = '\x1b[32m';
  static readonly YELLOW = '\x1b[33m';
  static readonly CYAN = '\x1b[36m';
  static readonly BOLD = '\x1b[1m';
  static readonly RESET = '\x1b[0m';

  static red = (s: string): string => `${Ansi.RED}${s}${Ansi.RESET}`;
  static green = (s: string): string => `${Ansi.GREEN}${s}${Ansi.RESET}`;
  static yellow = (s: string): string => `${Ansi.YELLOW}${s}${Ansi.RESET}`;
  static cyan = (s: string): string => `${Ansi.CYAN}${s}${Ansi.RESET}`;
  static bold = (s: string): string => `${Ansi.BOLD}${s}${Ansi.RESET}`;
}

export const PAD = {
  index: 4,
  operation: 7,
  protocol: 6,
  ipv4: 15,
  wildcard: 15,
  portCond: 14,
} as const;
