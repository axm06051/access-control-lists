import { Ansi, Operation, PAD, ReservedRanges } from '../acl/constants';
import type { AclKind, AclRange, BitIndex, OctetIndex, PortOperator } from '../acl/constants';

export function operationName(op: Operation): string {
  return Operation[op];
}

export function inferKindFromNumber(id: number): AclKind {
  const inRange = (n: number, { start, stop }: AclRange): boolean => ((n - start) | (stop - n)) >= 0;

  for (const [kind, ranges] of Object.entries(ReservedRanges)) {
    if (ranges.some((r) => inRange(id, r))) return kind as AclKind;
  }
  throw new RangeError(
    `ACL number ${id} is not in a reserved range. ` + `Standard: 1-99, 1300-1999. Extended: 100-199, 2000-2699.`
  );
}
