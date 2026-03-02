export type PortClassification = 'system' | 'user' | 'dynamic';

export function classifyPort(port: number): PortClassification {
  if (port >= 0 && port <= 1023) return 'system';
  if (port >= 1024 && port <= 49151) return 'user';
  return 'dynamic';
}
