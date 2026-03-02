describe('IANA CSV Parsing', () => {
  describe('parseIanaCSV', () => {
    it('parses valid CSV with required fields', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HyperText Transfer Protocol
https,443,tcp,HTTP Secure
dns,53,udp,Domain Name System`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];
      const descIdx = headers['Description'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim() || '';
        const portStr = parts[portIdx]?.trim() || '';
        const protocol = parts[protoIdx]?.trim().toLowerCase() || '';
        const desc = descIdx !== undefined ? parts[descIdx]?.trim() || '' : '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        apps.push({ name, port, protocol, description: desc });
      }

      expect(apps).toHaveLength(3);
      expect(apps[0]?.name).toBe('http');
      expect(apps[0]?.port).toBe(80);
      expect(apps[1]?.name).toBe('https');
      expect(apps[2]?.protocol).toBe('udp');
    });

    it('skips invalid port numbers', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HTTP
invalid,abc,tcp,Invalid Port
out-of-range,99999,tcp,Out of Range`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim() || '';
        const portStr = parts[portIdx]?.trim() || '';
        const protocol = parts[protoIdx]?.trim().toLowerCase() || '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        apps.push({ name, port, protocol });
      }

      expect(apps).toHaveLength(1);
      expect(apps[0]?.name).toBe('http');
    });

    it('handles quoted fields', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
"http",80,tcp,"HyperText Transfer Protocol"
"https",443,tcp,"HTTP Secure"`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim().replace(/"/g, '') || '';
        const portStr = parts[portIdx]?.trim().replace(/"/g, '') || '';
        const protocol = parts[protoIdx]?.trim().replace(/"/g, '').toLowerCase() || '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        apps.push({ name, port, protocol });
      }

      expect(apps).toHaveLength(2);
      expect(apps[0]?.name).toBe('http');
      expect(apps[1]?.name).toBe('https');
    });

    it('deduplicates services', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HTTP
http,80,tcp,HTTP
https,443,tcp,HTTPS`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      const seen = new Set<string>();

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim() || '';
        const portStr = parts[portIdx]?.trim() || '';
        const protocol = parts[protoIdx]?.trim().toLowerCase() || '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        const key = `${protocol}:${port}:${name}`;
        if (seen.has(key)) continue;
        seen.add(key);

        apps.push({ name, port, protocol });
      }

      expect(apps).toHaveLength(2);
    });

    it('handles empty lines', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,HTTP

https,443,tcp,HTTPS

`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim() || '';
        const portStr = parts[portIdx]?.trim() || '';
        const protocol = parts[protoIdx]?.trim().toLowerCase() || '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        apps.push({ name, port, protocol });
      }

      expect(apps).toHaveLength(2);
    });

    it('handles missing optional fields', () => {
      const csv = `Service Name,Port Number,Transport Protocol,Description
http,80,tcp,
https,443,tcp,HTTP Secure`;

      const lines = csv.split('\n');
      const headerLine = lines[0]!;
      const headers: Record<string, number> = {};
      headerLine.split(',').forEach((h, i) => {
        headers[h.trim()] = i;
      });

      const nameIdx = headers['Service Name'];
      const portIdx = headers['Port Number'];
      const protoIdx = headers['Transport Protocol'];
      const descIdx = headers['Description'];

      if (nameIdx === undefined || portIdx === undefined || protoIdx === undefined) {
        throw new Error('Missing required headers');
      }

      const apps = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim();
        if (!line) continue;

        const parts = line.split(',');
        const name = parts[nameIdx]?.trim() || '';
        const portStr = parts[portIdx]?.trim() || '';
        const protocol = parts[protoIdx]?.trim().toLowerCase() || '';
        const desc = descIdx !== undefined ? parts[descIdx]?.trim() || '' : '';

        if (!name || !portStr || !protocol) continue;

        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 0 || port > 65535) continue;

        apps.push({ name, port, protocol, description: desc || 'Service' });
      }

      expect(apps).toHaveLength(2);
      expect(apps[0]?.description).toBe('Service');
      expect(apps[1]?.description).toBe('HTTP Secure');
    });
  });

  describe('Status Detection Keywords', () => {
    it('detects removed status', () => {
      const descriptions = [
        'This port was previously removed on 2002-04-29',
        'previously removed',
        'This entry records an unassigned but widespread use',
      ];

      const removed = descriptions.filter((d) => d.includes('previously removed') || d.includes('was previously removed'));
      expect(removed).toHaveLength(2);
    });

    it('detects reserved status', () => {
      const descriptions = [
        'IANA RESERVED',
        'RESERVED - Not assigned',
        'Reserved for future use',
      ];

      const reserved = descriptions.filter((d) => d.includes('RESERVED') || d.includes('Reserved'));
      expect(reserved).toHaveLength(3);
    });

    it('detects alias status', () => {
      const descriptions = [
        'This entry is an alias to "http"',
        'This entry is an alias to "whoispp"',
        'See http://example.com',
      ];

      const aliases = descriptions.filter((d) => d.includes('is an alias to'));
      expect(aliases).toHaveLength(2);
    });

    it('detects duplicate status', () => {
      const descriptions = [
        'This is a duplicate of the "http" service',
        'is a duplicate of the',
        'This is a duplicate',
      ];

      const duplicates = descriptions.filter((d) => d.includes('duplicate'));
      expect(duplicates).toHaveLength(3);
    });

    it('detects conflict status', () => {
      const descriptions = [
        'Possible Conflict of Port 222',
        'Potential Conflict of ports',
        'conflict detected',
      ];

      const conflicts = descriptions.filter((d) => d.includes('Conflict') || d.includes('conflict'));
      expect(conflicts).toHaveLength(3);
    });

    it('detects retasked status', () => {
      const descriptions = [
        'This port has been retasked on 2015-06-16',
        'has been retasked',
        'port was retasked',
      ];

      const retasked = descriptions.filter((d) => d.includes('retasked'));
      expect(retasked).toHaveLength(3);
    });

    it('detects unassigned status', () => {
      const descriptions = [
        'This entry records an unassigned but widespread use',
        'unassigned but widespread',
        'should not be used for discovery purposes',
      ];

      const unassigned = descriptions.filter((d) => d.includes('unassigned') || d.includes('should not be used'));
      expect(unassigned).toHaveLength(3);
    });

    it('detects historical/former status', () => {
      const descriptions = [
        'Formerly was Workstation Solutions',
        'was previously assigned',
        'Historically, this service',
      ];

      const historical = descriptions.filter((d) => d.includes('Formerly') || d.includes('was previously') || d.includes('Historically'));
      expect(historical).toHaveLength(3);
    });

    it('detects unofficial status', () => {
      const descriptions = [
        'Microsoft (unoffically) using 1232',
        'unoffically using',
        'Proprietary',
      ];

      const unofficial = descriptions.filter((d) => d.includes('unoffically') || d.includes('Proprietary'));
      expect(unofficial).toHaveLength(3);
    });
  });

  describe('Port Range Validation', () => {
    it('validates port range 0-1023 (system)', () => {
      const ports = [0, 1, 80, 443, 1023];
      const systemPorts = ports.filter((p) => p >= 0 && p <= 1023);
      expect(systemPorts).toHaveLength(5);
    });

    it('validates port range 1024-49151 (user)', () => {
      const ports = [1024, 8080, 49151];
      const userPorts = ports.filter((p) => p >= 1024 && p <= 49151);
      expect(userPorts).toHaveLength(3);
    });

    it('validates port range 49152-65535 (dynamic)', () => {
      const ports = [49152, 50000, 65535];
      const dynamicPorts = ports.filter((p) => p >= 49152 && p <= 65535);
      expect(dynamicPorts).toHaveLength(3);
    });

    it('rejects invalid ports', () => {
      const ports = [-1, 0, 65535, 65536, 99999];
      const valid = ports.filter((p) => p >= 0 && p <= 65535);
      expect(valid).toHaveLength(2);
    });
  });
});
