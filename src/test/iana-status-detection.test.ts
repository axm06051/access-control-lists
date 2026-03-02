import { IANAStatusDetector, type IANAServiceEntry } from '@/domains/iana';

describe('IANA Status Detection', () => {
  let detector: IANAStatusDetector;

  beforeEach(() => {
    detector = new IANAStatusDetector();
  });

  describe('Removal Status Detection', () => {
    it('detects removed status from exact phrase', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'old-service',
        'Port Number': '9999',
        'Transport Protocol': 'tcp',
        Description: 'This port was previously removed on 2002-04-29',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('removed');
    });

    it('detects removed status from keyword', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'deprecated-service',
        'Port Number': '8888',
        'Transport Protocol': 'tcp',
        Description: 'This service has been deprecated',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('removed');
    });

    it('detects retasked status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'retasked-service',
        'Port Number': '7777',
        'Transport Protocol': 'tcp',
        Description: 'This port has been retasked on 2015-06-16',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('removed');
    });
  });

  describe('Reserved Status Detection', () => {
    it('detects reserved status from exact phrase', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'reserved-port',
        'Port Number': '1234',
        'Transport Protocol': 'tcp',
        Description: 'IANA RESERVED',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('reserved');
    });

    it('detects reserved status from keyword', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'reserved-service',
        'Port Number': '5555',
        'Transport Protocol': 'tcp',
        Description: 'Reserved for future use',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('reserved');
    });
  });

  describe('Alias Status Detection', () => {
    it('detects alias status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'alias-service',
        'Port Number': '6666',
        'Transport Protocol': 'tcp',
        Description: 'This entry is an alias to "http"',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('alias');
    });
  });

  describe('Duplicate Status Detection', () => {
    it('detects duplicate status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'dup-service',
        'Port Number': '7777',
        'Transport Protocol': 'tcp',
        Description: 'This is a duplicate of the "http" service and should not be used for discovery purposes',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('duplicate');
    });
  });

  describe('Conflict Status Detection', () => {
    it('detects conflict status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'conflict-service',
        'Port Number': '8888',
        'Transport Protocol': 'tcp',
        Description: 'Possible Conflict of Port 222 with "Masqdialer"',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('conflict');
    });
  });

  describe('Historical Status Detection', () => {
    it('detects historical status from formerly', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'historical-service',
        'Port Number': '9999',
        'Transport Protocol': 'tcp',
        Description: 'Formerly was Workstation Solutions',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('historical');
    });

    it('detects historical status from assigned long ago', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'old-service',
        'Port Number': '1111',
        'Transport Protocol': 'tcp',
        Description: '(assigned long ago)',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('historical');
    });
  });

  describe('Unofficial Status Detection', () => {
    it('detects unofficial status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'unofficial-service',
        'Port Number': '2222',
        'Transport Protocol': 'tcp',
        Description: 'Microsoft (unoffically) using 1232',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('unofficial');
    });

    it('detects unofficial status from widespread use', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'widespread-service',
        'Port Number': '3333',
        'Transport Protocol': 'tcp',
        Description: 'This entry records an unassigned but widespread use',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('unofficial');
    });
  });

  describe('Unassigned Status Detection', () => {
    it('detects unassigned status', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'unassigned-service',
        'Port Number': '4444',
        'Transport Protocol': 'tcp',
        Description: 'This entry records an unassigned but widespread use',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.detectStatus(entry)).toBe('unofficial');
    });
  });

  describe('Active Status Detection', () => {
    it('detects active status for clean entries', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'http',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'HyperText Transfer Protocol',
        Assignee: 'IANA',
        Contact: '',
        'Registration Date': '1985-01-01',
        'Modification Date': '',
        Reference: '[RFC7230]',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'Defined TXT keys: u=<username> p=<password> path=<path>',
      };

      expect(detector.detectStatus(entry)).toBe('active');
    });
  });

  describe('shouldInclude', () => {
    it('excludes removed services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'removed-service',
        'Port Number': '9999',
        'Transport Protocol': 'tcp',
        Description: 'This port was previously removed',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.shouldInclude(entry)).toBe(false);
    });

    it('excludes reserved services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'reserved-service',
        'Port Number': '1234',
        'Transport Protocol': 'tcp',
        Description: 'IANA RESERVED',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.shouldInclude(entry)).toBe(false);
    });

    it('includes active services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'http',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'HyperText Transfer Protocol',
        Assignee: 'IANA',
        Contact: '',
        'Registration Date': '1985-01-01',
        'Modification Date': '',
        Reference: '[RFC7230]',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.shouldInclude(entry)).toBe(true);
    });

    it('excludes entries without service name', () => {
      const entry: IANAServiceEntry = {
        'Service Name': '',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'No service name',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.shouldInclude(entry)).toBe(false);
    });

    it('excludes entries without port number', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'service',
        'Port Number': '',
        'Transport Protocol': 'tcp',
        Description: 'No port number',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };

      expect(detector.shouldInclude(entry)).toBe(false);
    });
  });
});
