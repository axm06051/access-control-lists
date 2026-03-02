import { IANAStatusDetector, type IANAServiceEntry } from '@/domains/iana/status-detector';
import { parseCSVLine, cleanCSVValue, parseHeaders } from '@/domains/iana/csv-parser';
import { IANAParser, ServiceRegistry } from '@/domains/iana/services';
import type { Application } from '@/domains/iana/types';

beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('CSV Parser', () => {
  describe('parseCSVLine', () => {
    it('parses simple comma-separated values', () => {
      expect(parseCSVLine('http,80,tcp')).toEqual(['http', '80', 'tcp']);
    });

    it('handles quoted values with commas', () => {
      expect(parseCSVLine('"HyperText Transfer Protocol, HTTP",80,tcp')).toEqual([
        'HyperText Transfer Protocol, HTTP',
        '80',
        'tcp',
      ]);
    });

    it('handles empty fields', () => {
      expect(parseCSVLine('http,80,,tcp')).toEqual(['http', '80', '', 'tcp']);
    });

    it('handles quoted empty fields', () => {
      expect(parseCSVLine('http,80,"",tcp')).toEqual(['http', '80', '', 'tcp']);
    });

    it('handles trailing commas', () => {
      expect(parseCSVLine('http,80,tcp,')).toEqual(['http', '80', 'tcp', '']);
    });
  });

  describe('cleanCSVValue', () => {
    it('removes surrounding quotes', () => {
      expect(cleanCSVValue('"http"')).toBe('http');
    });

    it('trims whitespace', () => {
      expect(cleanCSVValue('  http  ')).toBe('http');
    });

    it('handles undefined', () => {
      expect(cleanCSVValue(undefined)).toBe('');
    });

    it('removes quotes and trims', () => {
      expect(cleanCSVValue('  "http"  ')).toBe('"http"');
    });
  });

  describe('parseHeaders', () => {
    it('creates header index map', () => {
      const headers = parseHeaders('Service Name,Port Number,Transport Protocol');
      expect(headers['Service Name']).toBe(0);
      expect(headers['Port Number']).toBe(1);
      expect(headers['Transport Protocol']).toBe(2);
    });

    it('handles quoted headers', () => {
      const headers = parseHeaders('"Service Name","Port Number","Transport Protocol"');
      expect(headers['Service Name']).toBe(0);
      expect(headers['Port Number']).toBe(1);
    });

    it('handles headers with spaces', () => {
      const headers = parseHeaders('Service Name, Port Number , Transport Protocol');
      expect(headers['Service Name']).toBe(0);
      expect(headers['Port Number']).toBe(1);
    });
  });
});

describe('IANA Status Detector', () => {
  const detector = new IANAStatusDetector();

  describe('detectStatus', () => {
    it('detects active services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'http',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'HyperText Transfer Protocol',
        Assignee: 'IETF',
        Contact: '',
        'Registration Date': '1985-01-01',
        'Modification Date': '',
        Reference: 'RFC 7230',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };
      expect(detector.detectStatus(entry)).toBe('active');
    });

    it('detects removed services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'old-service',
        'Port Number': '999',
        'Transport Protocol': 'tcp',
        Description: 'Old service',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'This port was previously removed',
      };
      expect(detector.detectStatus(entry)).toBe('removed');
    });

    it('detects reserved ports', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'reserved',
        'Port Number': '1',
        'Transport Protocol': 'tcp',
        Description: 'Reserved',
        Assignee: 'IANA',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'IANA RESERVED',
      };
      expect(detector.detectStatus(entry)).toBe('reserved');
    });

    it('detects duplicate services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'dup-service',
        'Port Number': '500',
        'Transport Protocol': 'tcp',
        Description: 'Duplicate service',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'is a duplicate of the service below',
      };
      expect(detector.detectStatus(entry)).toBe('duplicate');
    });

    it('detects historical services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'old-proto',
        'Port Number': '100',
        'Transport Protocol': 'tcp',
        Description: 'Old protocol',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'Formerly was used for X',
      };
      expect(detector.detectStatus(entry)).toBe('historical');
    });

    it('detects conflict services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'conflict-service',
        'Port Number': '200',
        'Transport Protocol': 'tcp',
        Description: 'Conflicting service',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'Possible Conflict of Port',
      };
      expect(detector.detectStatus(entry)).toBe('conflict');
    });
  });

  describe('shouldInclude', () => {
    it('includes active services with valid data', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'http',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'HyperText Transfer Protocol',
        Assignee: 'IETF',
        Contact: '',
        'Registration Date': '1985-01-01',
        'Modification Date': '',
        Reference: 'RFC 7230',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': '',
      };
      expect(detector.shouldInclude(entry)).toBe(true);
    });

    it('excludes removed services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'removed-service',
        'Port Number': '999',
        'Transport Protocol': 'tcp',
        Description: 'Removed',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'This port was previously removed',
      };
      expect(detector.shouldInclude(entry)).toBe(false);
    });

    it('excludes entries without service name', () => {
      const entry: IANAServiceEntry = {
        'Service Name': '',
        'Port Number': '80',
        'Transport Protocol': 'tcp',
        Description: 'No name',
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
        'Service Name': 'http',
        'Port Number': '',
        'Transport Protocol': 'tcp',
        Description: 'No port',
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

    it('excludes reserved ports', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'reserved',
        'Port Number': '1',
        'Transport Protocol': 'tcp',
        Description: 'Reserved',
        Assignee: 'IANA',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'IANA RESERVED',
      };
      expect(detector.shouldInclude(entry)).toBe(false);
    });

    it('excludes duplicate services', () => {
      const entry: IANAServiceEntry = {
        'Service Name': 'dup',
        'Port Number': '500',
        'Transport Protocol': 'tcp',
        Description: 'Duplicate',
        Assignee: '',
        Contact: '',
        'Registration Date': '',
        'Modification Date': '',
        Reference: '',
        'Service Code': '',
        'Unauthorized Use Reported': '',
        'Assignment Notes': 'is a duplicate of the service below',
      };
      expect(detector.shouldInclude(entry)).toBe(false);
    });
  });
});

describe('IANA Parser', () => {
  const parser = new IANAParser();

  describe('parseCSV', () => {
    it('returns empty map for empty file', async () => {
      const mockFile = jest.spyOn(require('fs').promises, 'readFile').mockResolvedValue('');
      const result = await parser.parseCSV({ filePath: 'test.csv' });
      expect(result.size).toBe(4);
      expect(result.get('tcp')).toEqual([]);
      mockFile.mockRestore();
    });

    it('parses valid CSV entries', async () => {
      const csvContent = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HyperText Transfer Protocol
https,443,tcp,HTTP Secure
dns,53,udp,Domain Name System`;

      const mockFile = jest.spyOn(require('fs').promises, 'readFile').mockResolvedValue(csvContent);
      const result = await parser.parseCSV({ filePath: 'test.csv' });

      const tcpApps = result.get('tcp') || [];
      expect(tcpApps.length).toBeGreaterThan(0);
      expect(tcpApps.some((app) => app.name === 'http')).toBe(true);

      mockFile.mockRestore();
    });

    it('filters by protocol', async () => {
      const csvContent = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HyperText Transfer Protocol
dns,53,udp,Domain Name System`;

      const mockFile = jest.spyOn(require('fs').promises, 'readFile').mockResolvedValue(csvContent);
      const result = await parser.parseCSV({
        filePath: 'test.csv',
        filterBy: { protocol: ['tcp'] },
      });

      const tcpApps = result.get('tcp') || [];
      const udpApps = result.get('udp') || [];
      expect(tcpApps.length).toBeGreaterThan(0);
      expect(udpApps.length).toBe(0);

      mockFile.mockRestore();
    });

    it('filters by port range', async () => {
      const csvContent = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HyperText Transfer Protocol
https,443,tcp,HTTP Secure
ssh,22,tcp,Secure Shell`;

      const mockFile = jest.spyOn(require('fs').promises, 'readFile').mockResolvedValue(csvContent);
      const result = await parser.parseCSV({
        filePath: 'test.csv',
        filterBy: { portMin: 50, portMax: 500 },
      });

      const tcpApps = result.get('tcp') || [];
      expect(tcpApps.every((app) => app.port >= 50 && app.port <= 500)).toBe(true);

      mockFile.mockRestore();
    });
  });
});

describe('Service Registry', () => {
  const registry = new ServiceRegistry();

  describe('initialization', () => {
    it('initializes with empty protocol maps', () => {
      const protocols = registry.getAllProtocols();
      expect(protocols).toContain('tcp');
      expect(protocols).toContain('udp');
      expect(protocols).toContain('sctp');
      expect(protocols).toContain('dccp');
    });

    it('returns empty arrays for unloaded protocols', () => {
      expect(registry.getProtocolApps('tcp')).toEqual([]);
      expect(registry.getProtocolApps('udp')).toEqual([]);
    });
  });

  describe('search', () => {
    it('searches by term', () => {
      const mockApps: Application[] = [
        { name: 'http', port: 80, description: 'HyperText Transfer Protocol', status: 'active' },
        { name: 'https', port: 443, description: 'HTTP Secure', status: 'active' },
        { name: 'ssh', port: 22, description: 'Secure Shell', status: 'active' },
      ];

      const registry = new ServiceRegistry();
      const results = registry.search({ searchTerm: 'http' });
      expect(results.length).toBeGreaterThanOrEqual(0);
    });

    it('searches by port range', () => {
      const results = registry.search({ portRange: { min: 1, max: 1024 } });
      expect(results.every((app) => app.port >= 1 && app.port <= 1024)).toBe(true);
    });

    it('searches by service name pattern', () => {
      const results = registry.search({ serviceNamePattern: /^http/ });
      expect(results.every((app) => /^http/.test(app.name))).toBe(true);
    });

    it('filters by status', () => {
      const results = registry.search({ status: ['active'] });
      expect(results.every((app) => app.status === 'active')).toBe(true);
    });
  });

  describe('getPortType', () => {
    it('classifies system ports (0-1023)', () => {
      expect(registry.getPortType(80)).toBe('system');
      expect(registry.getPortType(443)).toBe('system');
      expect(registry.getPortType(22)).toBe('system');
    });

    it('classifies user ports (1024-49151)', () => {
      expect(registry.getPortType(8080)).toBe('user');
      expect(registry.getPortType(3000)).toBe('user');
    });

    it('classifies dynamic ports (49152-65535)', () => {
      expect(registry.getPortType(50000)).toBe('dynamic');
      expect(registry.getPortType(65535)).toBe('dynamic');
    });
  });

  describe('exportToJSON', () => {
    it('exports data structure', () => {
      const exported = registry.exportToJSON();
      expect(exported).toHaveProperty('lastUpdated');
      expect(exported).toHaveProperty('protocols');
    });

    it('includes all protocols in export', () => {
      const exported = registry.exportToJSON() as any;
      expect(exported.protocols).toHaveProperty('tcp');
      expect(exported.protocols).toHaveProperty('udp');
      expect(exported.protocols).toHaveProperty('sctp');
      expect(exported.protocols).toHaveProperty('dccp');
    });
  });
});
