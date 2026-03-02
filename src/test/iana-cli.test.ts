import { ServiceRegistry, type Application } from '@/domains/iana';

describe('IANA CLI - Service Registry', () => {
  let registry: ServiceRegistry;

  beforeEach(() => {
    registry = new ServiceRegistry();
  });

  describe('addService', () => {
    it('adds a TCP service', () => {
      const app: Application = {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      };
      registry.addService('tcp', app);
      const results = registry.search({ portRange: { min: 80, max: 80 } });
      expect(results).toHaveLength(1);
      expect(results[0]?.name).toBe('http');
    });

    it('adds a UDP service', () => {
      const app: Application = {
        name: 'dns',
        port: 53,
        description: 'Domain Name System',
        status: 'active',
      };
      registry.addService('udp', app);
      const results = registry.search({ protocols: ['udp'] });
      expect(results.length).toBeGreaterThan(0);
    });

    it('adds multiple services to same protocol', () => {
      const apps: Application[] = [
        { name: 'http', port: 80, description: 'HTTP', status: 'active' },
        { name: 'https', port: 443, description: 'HTTPS', status: 'active' },
      ];
      apps.forEach((app) => registry.addService('tcp', app));
      const results = registry.search({});
      expect(results.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('search', () => {
    beforeEach(() => {
      const services: Application[] = [
        { name: 'http', port: 80, description: 'HTTP', status: 'active' },
        { name: 'https', port: 443, description: 'HTTPS', status: 'active' },
        { name: 'ssh', port: 22, description: 'Secure Shell', status: 'active' },
        { name: 'telnet', port: 23, description: 'Telnet', status: 'active' },
      ];
      services.forEach((app) => registry.addService('tcp', app));
    });

    it('searches by term', () => {
      const results = registry.search({ searchTerm: 'http' });
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((r) => r.name.includes('http'))).toBe(true);
    });

    it('searches by port range', () => {
      const results = registry.search({ portRange: { min: 20, max: 100 } });
      expect(results.length).toBeGreaterThan(0);
      expect(results.every((r) => r.port >= 20 && r.port <= 100)).toBe(true);
    });

    it('filters by protocol', () => {
      registry.addService('udp', {
        name: 'dns',
        port: 53,
        description: 'DNS',
        status: 'active',
      });
      const tcpResults = registry.search({ protocols: ['tcp'] });
      const udpResults = registry.search({ protocols: ['udp'] });
      expect(tcpResults.every((r) => r.name !== 'dns')).toBe(true);
      expect(udpResults.some((r) => r.name === 'dns')).toBe(true);
    });

    it('filters by status', () => {
      registry.addService('tcp', {
        name: 'deprecated-service',
        port: 999,
        description: 'Old service',
        status: 'deprecated',
      });
      const activeResults = registry.search({ status: ['active'] });
      const deprecatedResults = registry.search({ status: ['deprecated'] });
      expect(activeResults.every((r) => r.status === 'active')).toBe(true);
      expect(deprecatedResults.some((r) => r.status === 'deprecated')).toBe(true);
    });

    it('filters by port type (system)', () => {
      const results = registry.search({ portType: ['system'] });
      expect(results.every((r) => r.port >= 0 && r.port <= 1023)).toBe(true);
    });

    it('filters by port type (user)', () => {
      const results = registry.search({ portType: ['user'] });
      expect(results.every((r) => r.port >= 1024 && r.port <= 49151)).toBe(true);
    });

    it('filters by port type (dynamic)', () => {
      const results = registry.search({ portType: ['dynamic'] });
      expect(results.every((r) => r.port >= 49152 && r.port <= 65535)).toBe(true);
    });

    it('searches with regex pattern', () => {
      const results = registry.search({ serviceNamePattern: /^h/ });
      expect(results.every((r) => r.name.startsWith('h'))).toBe(true);
    });
  });

  describe('getStats', () => {
    it('returns empty stats for empty registry', () => {
      const stats = registry.getStats();
      expect(stats.totalServices).toBe(0);
      expect(stats.protocolCounts.tcp).toBe(0);
      expect(stats.protocolCounts.udp).toBe(0);
    });

    it('counts services by protocol', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });
      registry.addService('tcp', {
        name: 'https',
        port: 443,
        description: 'HTTPS',
        status: 'active',
      });
      registry.addService('udp', {
        name: 'dns',
        port: 53,
        description: 'DNS',
        status: 'active',
      });

      const stats = registry.getStats();
      expect(stats.totalServices).toBe(3);
      expect(stats.protocolCounts.tcp).toBe(2);
      expect(stats.protocolCounts.udp).toBe(1);
    });

    it('tracks last updated timestamp', () => {
      const before = new Date();
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });
      const after = new Date();

      const stats = registry.getStats();
      expect(stats.lastUpdated).not.toBeNull();
      expect(stats.lastUpdated!.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(stats.lastUpdated!.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('updateService', () => {
    it('updates service properties', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });

      const updated = registry.updateService('tcp', 80, {
        description: 'HyperText Transfer Protocol',
        status: 'deprecated',
      });

      expect(updated).toBe(true);
      const results = registry.search({ portRange: { min: 80, max: 80 } });
      expect(results[0]?.description).toBe('HyperText Transfer Protocol');
      expect(results[0]?.status).toBe('deprecated');
    });

    it('returns false for non-existent service', () => {
      const updated = registry.updateService('tcp', 9999, { status: 'active' });
      expect(updated).toBe(false);
    });
  });

  describe('deleteService', () => {
    it('deletes service by port', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });

      const deleted = registry.deleteService('tcp', 80);
      expect(deleted).toBe(true);

      const results = registry.search({ portRange: { min: 80, max: 80 } });
      expect(results).toHaveLength(0);
    });

    it('deletes service by port and name', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });
      registry.addService('tcp', {
        name: 'http-alt',
        port: 80,
        description: 'HTTP Alt',
        status: 'active',
      });

      const deleted = registry.deleteService('tcp', 80, 'http');
      expect(deleted).toBe(true);

      const results = registry.search({ portRange: { min: 80, max: 80 } });
      expect(results).toHaveLength(1);
      expect(results[0]?.name).toBe('http-alt');
    });

    it('returns false for non-existent service', () => {
      const deleted = registry.deleteService('tcp', 9999);
      expect(deleted).toBe(false);
    });
  });

  describe('clear', () => {
    it('removes all services', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });
      registry.addService('udp', {
        name: 'dns',
        port: 53,
        description: 'DNS',
        status: 'active',
      });

      registry.clear();

      const stats = registry.getStats();
      expect(stats.totalServices).toBe(0);
    });
  });

  describe('exportToJSON', () => {
    it('exports services as JSON', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });

      const json = registry.exportToJSON();
      expect(json).toHaveProperty('protocols');
      expect(json).toHaveProperty('lastUpdated');
    });
  });

  describe('importFromJSON', () => {
    it('imports services from JSON', () => {
      const data = {
        protocols: {
          tcp: {
            '80': [
              {
                name: 'http',
                port: 80,
                description: 'HTTP',
                status: 'active',
              },
            ],
          },
        },
        lastUpdated: new Date().toISOString(),
      };

      registry.importFromJSON(data);

      const results = registry.search({ portRange: { min: 80, max: 80 } });
      expect(results).toHaveLength(1);
      expect(results[0]?.name).toBe('http');
    });
  });

  describe('Port Classification', () => {
    it('classifies system ports (0-1023)', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });

      const portType = registry.getPortType(80);
      expect(portType).toBe('system');
    });

    it('classifies user ports (1024-49151)', () => {
      registry.addService('tcp', {
        name: 'custom',
        port: 8080,
        description: 'Custom',
        status: 'active',
      });

      const portType = registry.getPortType(8080);
      expect(portType).toBe('user');
    });

    it('classifies dynamic ports (49152-65535)', () => {
      registry.addService('tcp', {
        name: 'ephemeral',
        port: 50000,
        description: 'Ephemeral',
        status: 'active',
      });

      const portType = registry.getPortType(50000);
      expect(portType).toBe('dynamic');
    });
  });

  describe('Service Status Detection', () => {
    it('identifies active services', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });

      const results = registry.search({ status: ['active'] });
      expect(results.some((r) => r.name === 'http')).toBe(true);
    });

    it('identifies deprecated services', () => {
      registry.addService('tcp', {
        name: 'old-service',
        port: 999,
        description: 'This port was previously removed',
        status: 'deprecated',
      });

      const results = registry.search({ status: ['deprecated'] });
      expect(results.some((r) => r.name === 'old-service')).toBe(true);
    });

    it('identifies reserved services', () => {
      registry.addService('tcp', {
        name: 'reserved-port',
        port: 1234,
        description: 'IANA RESERVED',
        status: 'reserved',
      });

      const results = registry.search({ status: ['reserved'] });
      expect(results.some((r) => r.name === 'reserved-port')).toBe(true);
    });

    it('identifies unassigned services', () => {
      registry.addService('tcp', {
        name: 'unassigned',
        port: 5555,
        description: 'This entry records an unassigned but widespread use',
        status: 'unassigned',
      });

      const results = registry.search({ status: ['unassigned'] });
      expect(results.some((r) => r.name === 'unassigned')).toBe(true);
    });

    it('identifies alias services', () => {
      registry.addService('tcp', {
        name: 'alias-service',
        port: 6666,
        description: 'This entry is an alias to "http"',
        status: 'alias',
      });

      const results = registry.search({ status: ['alias'] });
      expect(results.some((r) => r.name === 'alias-service')).toBe(true);
    });

    it('identifies duplicate services', () => {
      registry.addService('tcp', {
        name: 'dup-service',
        port: 7777,
        description: 'This is a duplicate of the "http" service',
        status: 'duplicate',
      });

      const results = registry.search({ status: ['duplicate'] });
      expect(results.some((r) => r.name === 'dup-service')).toBe(true);
    });

    it('identifies conflict services', () => {
      registry.addService('tcp', {
        name: 'conflict-service',
        port: 8888,
        description: 'Possible Conflict of Port 8888',
        status: 'conflict',
      });

      const results = registry.search({ status: ['conflict'] });
      expect(results.some((r) => r.name === 'conflict-service')).toBe(true);
    });
  });

  describe('Multiple Protocol Support', () => {
    it('stores same service on multiple protocols', () => {
      const app: Application = {
        name: 'dns',
        port: 53,
        description: 'Domain Name System',
        status: 'active',
      };
      registry.addService('tcp', app);
      registry.addService('udp', app);

      const tcpResults = registry.search({ protocols: ['tcp'] });
      const udpResults = registry.search({ protocols: ['udp'] });

      expect(tcpResults.some((r) => r.name === 'dns')).toBe(true);
      expect(udpResults.some((r) => r.name === 'dns')).toBe(true);
    });

    it('searches across all protocols', () => {
      registry.addService('tcp', {
        name: 'http',
        port: 80,
        description: 'HTTP',
        status: 'active',
      });
      registry.addService('udp', {
        name: 'dns',
        port: 53,
        description: 'DNS',
        status: 'active',
      });

      const results = registry.search({});
      expect(results.length).toBeGreaterThanOrEqual(2);
    });
  });
});
