import fs from 'fs';
import https from 'https';
import { classifyPort } from '../shared/port-classifier';
import { parseCSVLine, cleanCSVValue, parseHeaders } from './csv-parser';
import { IANAStatusDetector, type IANAServiceEntry } from './status-detector';
import type { L4Protocol, Application, ParserOptions, UpdateOptions, UpdateStats, FilterOptions, SortOptions, PortType } from './types';

const PROTOCOLS: L4Protocol[] = ['tcp', 'udp', 'sctp', 'dccp'];

function cleanValue(value: string | undefined): string {
  return cleanCSVValue(value);
}

function buildApplication(entry: IANAServiceEntry, detector: IANAStatusDetector): Application {
  const parts = [entry['Description'], entry['Reference'] && `[${entry['Reference']}]`, entry['Registration Date'] && `Registered: ${entry['Registration Date']}`, entry['Modification Date'] && `Modified: ${entry['Modification Date']}`].filter(Boolean);

  return {
    name: entry['Service Name'],
    port: parseInt(entry['Port Number'], 10),
    description: parts.join(' | '),
    status: detector.detectStatus(entry),
    registrationDate: entry['Registration Date'] || undefined,
    modificationDate: entry['Modification Date'] || undefined,
    reference: entry['Reference'] || undefined,
    notes: entry['Assignment Notes'] || undefined,
  };
}

export class IANAParser {
  private detector = new IANAStatusDetector();

  async parseCSV(options: ParserOptions): Promise<Map<L4Protocol, Application[]>> {
    const results = new Map<L4Protocol, Application[]>();
    PROTOCOLS.forEach((p: L4Protocol) => results.set(p, []));

    const fileContent = await fs.promises.readFile(options.filePath, 'utf-8');
    const lines = fileContent.split('\n');
    if (lines.length === 0) return results;

    const headers = parseHeaders(lines[0]!);

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line?.trim()) continue;

      const entry = this.parseEntry(line, headers);
      if (!entry || !this.passesFilters(entry, options.filterBy) || !this.detector.shouldInclude(entry)) continue;

      const app = buildApplication(entry, this.detector);
      const protocols = entry['Transport Protocol'].split(',').map((p) => p.trim().toLowerCase() as L4Protocol);
      protocols.forEach((p) => results.get(p)?.push(app));
    }

    return results;
  }

  private parseEntry(line: string, headers: Record<string, number>): IANAServiceEntry | null {
    const values = parseCSVLine(line);
    const entry: Partial<IANAServiceEntry> = {};

    Object.entries(headers).forEach(([key, index]) => {
      (entry as any)[key] = cleanValue(values[index]);
    });

    if (!entry['Service Name'] || !entry['Port Number'] || !entry['Transport Protocol']) return null;
    return entry as IANAServiceEntry;
  }

  private passesFilters(entry: IANAServiceEntry, filters?: ParserOptions['filterBy']): boolean {
    if (!filters) return true;

    if (filters.protocol && !filters.protocol.includes(entry['Transport Protocol'].toLowerCase() as L4Protocol)) return false;

    const port = parseInt(entry['Port Number'], 10);
    if (isNaN(port) || (filters.portMin && port < filters.portMin) || (filters.portMax && port > filters.portMax)) return false;
    if (filters.serviceNameRegex && !filters.serviceNameRegex.test(entry['Service Name'])) return false;

    return true;
  }
}

export class IANAUpdater {
  private readonly defaultUrl = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv';
  private updateIntervalMs: number;
  private detector = new IANAStatusDetector();

  constructor(private options: UpdateOptions) {
    this.updateIntervalMs = (options.updateIntervalDays || 30) * 24 * 60 * 60 * 1000;
  }

  async checkForUpdates(): Promise<boolean> {
    try {
      if (!this.needsUpdate()) return false;
      await this.performUpdate();
      return true;
    } catch (error) {
      this.options.onUpdateError?.(error as Error);
      return false;
    }
  }

  async forceUpdate(): Promise<UpdateStats> {
    return this.performUpdate();
  }

  private needsUpdate(): boolean {
    if (!fs.existsSync(this.options.localPath)) return true;
    const lastModified = fs.statSync(this.options.localPath).mtime;
    return new Date().getTime() - lastModified.getTime() >= this.updateIntervalMs;
  }

  private async performUpdate(): Promise<UpdateStats> {
    this.options.onUpdateStart?.();

    try {
      const url = this.options.ianaUrl || this.defaultUrl;
      const tempPath = this.options.localPath + '.tmp';

      await this.downloadFile(url, tempPath);
      if (this.options.backupPath && fs.existsSync(this.options.localPath)) {
        fs.copyFileSync(this.options.localPath, this.options.backupPath);
      }
      fs.renameSync(tempPath, this.options.localPath);

      const stats = await this.getStats(this.options.localPath);
      this.options.onUpdateComplete?.(true, stats);
      return stats;
    } catch (error) {
      this.options.onUpdateError?.(error as Error);
      this.options.onUpdateComplete?.(false, this.emptyStats());
      throw error;
    }
  }

  private async downloadFile(url: string, destination: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(destination);
      https.get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`HTTP ${response.statusCode}`));
          return;
        }
        response.pipe(file);
        file.on('finish', () => { file.close(); resolve(); });
      }).on('error', (error) => { fs.unlinkSync(destination); reject(error); });
    });
  }

  private async getStats(filePath: string): Promise<UpdateStats> {
    const fileContent = await fs.promises.readFile(filePath, 'utf-8');
    const lines = fileContent.split('\n');

    const counts = { tcp: 0, udp: 0, sctp: 0, dccp: 0, active: 0, excluded: 0 };

    for (let i = 1; i < Math.min(lines.length, 1000); i++) {
      const line = lines[i];
      if (!line?.trim()) continue;

      const values = line.split(',');
      if (values.length < 3) continue;

      const protocols = (values[2] || '').replace(/"/g, '').toUpperCase();
      const entry = this.buildStatsEntry(values);

      if (protocols.includes('TCP')) counts.tcp++;
      if (protocols.includes('UDP')) counts.udp++;
      if (protocols.includes('SCTP')) counts.sctp++;
      if (protocols.includes('DCCP')) counts.dccp++;

      this.detector.shouldInclude(entry) ? counts.active++ : counts.excluded++;
    }

    return {
      timestamp: new Date(),
      entriesProcessed: lines.length - 1,
      tcpEntries: counts.tcp,
      udpEntries: counts.udp,
      sctpEntries: counts.sctp,
      dccpEntries: counts.dccp,
      activeServices: counts.active,
      excludedServices: counts.excluded,
      fileSize: fileContent.length,
    };
  }

  private buildStatsEntry(values: string[]): IANAServiceEntry {
    return {
      'Service Name': cleanValue(values[0]),
      'Port Number': cleanValue(values[1]),
      'Transport Protocol': cleanValue(values[2]),
      Description: cleanValue(values[3]),
      Assignee: '',
      Contact: '',
      'Registration Date': '',
      'Modification Date': '',
      Reference: '',
      'Service Code': '',
      'Unauthorized Use Reported': '',
      'Assignment Notes': cleanValue(values[11]),
    };
  }

  private emptyStats(): UpdateStats {
    return {
      timestamp: new Date(),
      entriesProcessed: 0,
      tcpEntries: 0,
      udpEntries: 0,
      sctpEntries: 0,
      dccpEntries: 0,
      activeServices: 0,
      excludedServices: 0,
      fileSize: 0,
    };
  }
}

export class ServiceRegistry {
  private data: Map<L4Protocol, Application[]>;
  private lastUpdated: Date | null = null;

  constructor() {
    this.data = new Map();
    PROTOCOLS.forEach((p: L4Protocol) => this.data.set(p, []));
  }

  async loadFromIANA(filePath: string, options?: ParserOptions): Promise<void> {
    const parser = new IANAParser();
    this.data = await parser.parseCSV({ filePath, ...options });
    this.lastUpdated = new Date();
  }

  getProtocolApps(protocol: L4Protocol): Application[] {
    return this.data.get(protocol) || [];
  }

  getAllProtocols(): L4Protocol[] {
    return PROTOCOLS;
  }

  addService(protocol: L4Protocol, app: Application): void {
    const apps = this.data.get(protocol);
    if (apps) {
      apps.push(app);
      this.lastUpdated = new Date();
    }
  }

  addServices(protocol: L4Protocol, newApps: Application[]): void {
    const apps = this.data.get(protocol);
    if (apps) {
      apps.push(...newApps);
      this.lastUpdated = new Date();
    }
  }

  updateService(protocol: L4Protocol, port: number, updates: Partial<Application>): boolean {
    const apps = this.data.get(protocol);
    if (!apps) return false;

    const app = apps.find((a) => a.port === port);
    if (!app) return false;

    Object.assign(app, updates);
    this.lastUpdated = new Date();
    return true;
  }

  deleteService(protocol: L4Protocol, port: number, serviceName?: string): boolean {
    const apps = this.data.get(protocol);
    if (!apps) return false;

    const beforeLength = apps.length;
    if (serviceName) {
      const index = apps.findIndex((a) => a.port === port && a.name === serviceName);
      if (index >= 0) {
        apps.splice(index, 1);
      }
    } else {
      const index = apps.findIndex((a) => a.port === port);
      if (index >= 0) {
        apps.splice(index, 1);
      }
    }

    if (apps.length < beforeLength) {
      this.lastUpdated = new Date();
      return true;
    }
    return false;
  }

  search(filter: FilterOptions, sort?: SortOptions): Application[] {
    const protocols = filter.protocols || PROTOCOLS;
    let results: Application[] = [];

    for (const protocol of protocols) {
      const apps = this.data.get(protocol) || [];

      if (filter.searchTerm) {
        const lower = filter.searchTerm.toLowerCase();
        results.push(...apps.filter((app) =>
          app.name.toLowerCase().includes(lower) ||
          app.description.toLowerCase().includes(lower) ||
          app.port.toString().includes(lower) ||
          app.notes?.toLowerCase().includes(lower)
        ));
      } else if (filter.portRange) {
        results.push(...apps.filter((app) => app.port >= filter.portRange!.min && app.port <= filter.portRange!.max));
      } else if (filter.serviceNamePattern) {
        results.push(...apps.filter((app) => filter.serviceNamePattern!.test(app.name)));
      } else {
        results.push(...apps);
      }
    }

    if (filter.status?.length) results = results.filter((app) => app.status && filter.status!.includes(app.status));
    if (filter.portType?.length) results = results.filter((app) => filter.portType!.includes(this.getPortType(app.port)));

    if (sort) {
      results.sort((a, b) => {
        const aVal = a[sort.field];
        const bVal = b[sort.field];
        if (typeof aVal === 'string' && typeof bVal === 'string') return sort.order === 'desc' ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
        if (typeof aVal === 'number' && typeof bVal === 'number') return sort.order === 'desc' ? bVal - aVal : aVal - bVal;
        return 0;
      });
    }

    return results;
  }

  getStats(): { totalServices: number; protocolCounts: Record<L4Protocol, number>; lastUpdated: Date | null } {
    const stats = {
      totalServices: 0,
      protocolCounts: { tcp: 0, udp: 0, sctp: 0, dccp: 0 } as Record<L4Protocol, number>,
      lastUpdated: this.lastUpdated,
    };

    for (const protocol of PROTOCOLS) {
      const apps = this.data.get(protocol) || [];
      stats.protocolCounts[protocol] = apps.length;
      stats.totalServices += apps.length;
    }

    return stats;
  }

  getPortType(port: number): PortType {
    return classifyPort(port);
  }

  getLastUpdated(): Date | null {
    return this.lastUpdated;
  }

  clear(): void {
    PROTOCOLS.forEach((p: L4Protocol) => this.data.set(p, []));
    this.lastUpdated = new Date();
  }

  exportToJSON(): object {
    const exportData: any = { lastUpdated: this.lastUpdated?.toISOString(), protocols: {} };

    for (const [protocol, apps] of this.data.entries()) {
      const appsByPort: Record<number, Application[]> = {};
      apps.forEach((app) => {
        if (!appsByPort[app.port]) appsByPort[app.port] = [];
        appsByPort[app.port]!.push(app);
      });
      exportData.protocols[protocol] = appsByPort;
    }

    return exportData;
  }

  importFromJSON(data: any): void {
    this.clear();

    if (data.protocols) {
      for (const [protocol, appsByPort] of Object.entries(data.protocols)) {
        const apps = this.data.get(protocol as L4Protocol);
        if (!apps) continue;

        for (const [, portApps] of Object.entries(appsByPort as Record<string, Application[]>)) {
          apps.push(...(portApps as Application[]));
        }
      }
    }

    if (data.lastUpdated) {
      this.lastUpdated = new Date(data.lastUpdated);
    }
  }
}

export function setupUpdateCron(
  localPath: string,
  intervalHours: number = 24 * 30,
  onUpdate?: (stats: UpdateStats) => void
): IANAUpdater {
  const updater = new IANAUpdater({
    localPath,
    backupPath: `${localPath}.backup`,
    updateIntervalDays: intervalHours / 24,
    onUpdateComplete: (success, stats) => { if (success && onUpdate) onUpdate(stats); },
  });

  setTimeout(() => updater.checkForUpdates().catch(console.error), 5000);
  setInterval(() => updater.checkForUpdates().catch(console.error), intervalHours * 60 * 60 * 1000);

  return updater;
}
