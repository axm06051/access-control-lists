export type L4Protocol = 'tcp' | 'udp' | 'sctp' | 'dccp';
export type PortType = 'system' | 'user' | 'dynamic';
export type ServiceStatus = 'active' | 'reserved' | 'deprecated' | 'removed' | 'unassigned' | 'alias' | 'conflict' | 'duplicate' | 'historical' | 'unofficial';

export type IANAServiceEntry = {
  'Service Name': string;
  'Port Number': string;
  'Transport Protocol': string;
  Description: string;
  Assignee: string;
  Contact: string;
  'Registration Date': string;
  'Modification Date': string;
  Reference: string;
  'Service Code': string;
  'Unauthorized Use Reported': string;
  'Assignment Notes': string;
};

export type Application = {
  name: string;
  port: number;
  description: string;
  status?: ServiceStatus;
  registrationDate?: string | undefined;
  modificationDate?: string | undefined;
  reference?: string | undefined;
  notes?: string | undefined;
};

export type ParserOptions = {
  filePath: string;
  filterBy?: {
    protocol?: L4Protocol[];
    portMin?: number;
    portMax?: number;
    serviceNameRegex?: RegExp;
    status?: ServiceStatus[];
  };
  sortBy?: keyof Application;
  sortOrder?: 'asc' | 'desc';
};

export type UpdateOptions = {
  ianaUrl?: string;
  localPath: string;
  backupPath?: string;
  updateIntervalDays?: number;
  onUpdateStart?: () => void;
  onUpdateComplete?: (success: boolean, stats: UpdateStats) => void;
  onUpdateError?: (error: Error) => void;
};

export type UpdateStats = {
  timestamp: Date;
  entriesProcessed: number;
  tcpEntries: number;
  udpEntries: number;
  sctpEntries: number;
  dccpEntries: number;
  activeServices: number;
  excludedServices: number;
  fileSize: number;
};

export type FilterOptions = {
  protocols?: L4Protocol[];
  portRange?: { min: number; max: number };
  serviceNamePattern?: RegExp;
  searchTerm?: string;
  status?: ServiceStatus[];
  portType?: PortType[];
};

export type SortOptions = {
  field: keyof Application;
  order?: 'asc' | 'desc';
};
