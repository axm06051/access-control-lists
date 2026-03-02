import type { ServiceStatus, IANAServiceEntry } from './types';

export type { IANAServiceEntry };

const STATUS_KEYWORDS = {
  removal: [
    'removed', 'deleted', 'withdrawn', 'retired', 'obsoleted', 'deprecated',
    'unassigned', 'not be used', 'retasked', 'unused', 'inactive', 'reclaimed',
    'returned', 'reclassified'
  ],
  reserved: [
    'reserved', 'RESERVED', 'held', 'IANA', 'IANA RESERVED', 'Reserved port',
    'Reserved range', 'Reserved for', 'Reserved - Not assigned', 'Reserved for future use',
    'Reserved (System Port)', 'Reserved (Registered Port)', 'System Port', 'Registered Port'
  ],
  alias: [
    'alias to', 'is an alias to', 'This entry is an alias to', 'See http', 'See [RFC',
    'See [REFERENCE]', 'See DOCUMENT'
  ],
  duplicate: [
    'duplicate', 'is a duplicate', 'This is a duplicate of', 'is a duplicate of the'
  ],
  conflict: [
    'conflict', 'Possible Conflict', 'Potential Conflict', 'disputed', 'contested',
    'Possible Conflict of Port', 'Potential Conflict of ports'
  ],
  historical: [
    'formerly', 'Formerly was', 'was previously', 'previously', 'historically',
    'Historically,', 'legacy', 'early implementation', 'initial version', 'originally',
    'assigned long ago', 'grandfathered', 'Historically, this service'
  ],
  unofficial: [
    'widespread use', 'unoffically', 'unoffically using', 'does not meet the registry requirements',
    'Proprietary', 'primarily registered for', 'Microsoft (unoffically)', 'early implementation'
  ],
  modified: [
    'modified', 'updated', 'Modified:', 'Updated:', 'contact updated', 'New contact added'
  ]
};

const EXACT_PHRASES = [
  'previously removed', 'unassigned but widespread use', 'should not be used',
  'has been retasked', 'not be used for discovery purposes', 'previously assigned to application below',
  'was already previously assigned', 'This port was previously removed', 'port was previously updated',
  'This port has been retasked', 'is RESERVED', 'IANA RESERVED', 'RESERVED - Not assigned',
  'RESERVED for future use', 'Possible Conflict of Port', 'is a duplicate of the',
  'Formerly was', 'assigned long ago', 'initially created by', 'Microsoft (unoffically) using',
  'This entry records an unassigned but widespread use', 'This entry is an alias to',
  'This is a duplicate of the', 'This port has been retasked on', 'This port was previously removed on',
  'port was previously updated on', 'removed on', 'updated on', 'retasked on'
];

const REMOVAL_PATTERNS = [
  /this port was previously removed/i,
  /previously removed/i,
  /should not be used/i,
  /is a duplicate of/i,
  /unassigned but widespread/i,
  /has been retasked/i,
  /not be used for discovery/i,
  /withdrawn/i,
  /retired/i,
  /obsoleted/i,
  /deleted/i
];

const RESERVED_PATTERNS = [
  /is RESERVED/i,
  /IANA RESERVED/i,
  /RESERVED - Not assigned/i,
  /RESERVED for future use/i,
  /Port \d+ is RESERVED/i
];

const CONFLICT_PATTERNS = [
  /Possible Conflict of Port/i,
  /Potential Conflict of ports/i,
  /conflict/i
];

const DUPLICATE_PATTERNS = [
  /is a duplicate of the/i,
  /This is a duplicate/i,
  /duplicate/i
];

const ALIAS_PATTERNS = [
  /This entry is an alias to/i,
  /is an alias to/i,
  /See http:\/\//i,
  /See \[RFC/i
];

const HISTORICAL_PATTERNS = [
  /Formerly was/i,
  /was previously/i,
  /Historically, this service/i,
  /assigned long ago/i,
  /early implementation/i,
  /initial version/i
];

const UNOFFICIAL_PATTERNS = [
  /Microsoft \(unoffically\)/i,
  /unoffically using/i,
  /widespread use/i,
  /Proprietary/i,
  /does not meet the registry requirements/i
];

function buildSearchText(entry: IANAServiceEntry): string {
  return `${entry['Assignment Notes'] || ''} ${entry['Description'] || ''} ${entry['Service Name'] || ''} ${entry['Reference'] || ''} ${entry['Modification Date'] || ''}`.toLowerCase();
}

function hasKeyword(text: string, keywords: string[]): boolean {
  return keywords.some((k) => text.includes(k.toLowerCase()));
}

function getStatusFromPhrase(text: string): ServiceStatus {
  if (REMOVAL_PATTERNS.some((p) => p.test(text))) return 'removed';
  if (RESERVED_PATTERNS.some((p) => p.test(text))) return 'reserved';
  if (CONFLICT_PATTERNS.some((p) => p.test(text))) return 'conflict';
  if (DUPLICATE_PATTERNS.some((p) => p.test(text))) return 'duplicate';
  if (ALIAS_PATTERNS.some((p) => p.test(text))) return 'alias';
  if (HISTORICAL_PATTERNS.some((p) => p.test(text))) return 'historical';
  if (UNOFFICIAL_PATTERNS.some((p) => p.test(text))) return 'unofficial';
  if (text.includes('unassigned')) return 'unassigned';
  return 'active';
}

export class IANAStatusDetector {
  detectStatus(entry: IANAServiceEntry): ServiceStatus {
    const text = buildSearchText(entry);

    if (EXACT_PHRASES.some((p) => text.includes(p.toLowerCase()))) return getStatusFromPhrase(text);
    if (REMOVAL_PATTERNS.some((p) => p.test(text))) return 'removed';
    if (RESERVED_PATTERNS.some((p) => p.test(text))) return 'reserved';
    if (ALIAS_PATTERNS.some((p) => p.test(text))) return 'alias';
    if (DUPLICATE_PATTERNS.some((p) => p.test(text))) return 'duplicate';
    if (CONFLICT_PATTERNS.some((p) => p.test(text))) return 'conflict';
    if (HISTORICAL_PATTERNS.some((p) => p.test(text))) return 'historical';
    if (UNOFFICIAL_PATTERNS.some((p) => p.test(text))) return 'unofficial';
    if (hasKeyword(text, STATUS_KEYWORDS.removal)) return 'removed';
    if (hasKeyword(text, STATUS_KEYWORDS.reserved)) return 'reserved';
    if (hasKeyword(text, STATUS_KEYWORDS.unassigned)) return 'unassigned';

    return 'active';
  }

  shouldInclude(entry: IANAServiceEntry): boolean {
    const status = this.detectStatus(entry);
    const excludedStatuses: ServiceStatus[] = ['removed', 'reserved', 'unassigned', 'alias', 'duplicate', 'conflict'];
    
    if (excludedStatuses.includes(status)) return false;
    if (!entry['Service Name']?.trim()) return false;
    if (!entry['Port Number']?.trim()) return false;
    
    return !REMOVAL_PATTERNS.some((p) => p.test(entry['Assignment Notes'] || ''));
  }
}
