import { AclRange, PortOperator, OctetIndex, BitIndex, AclKind, AclIdType, Operation } from './constants';

export type { AclRange, PortOperator, OctetIndex, BitIndex };
export { AclKind, AclIdType, Operation };
export type L3Protocol = 'ip' | 'tcp' | 'udp' | 'icmp' | 'ospf';

export type PortCondition = { op: Exclude<PortOperator, 'range'>; port: number } | { op: 'range'; portA: number; portB: number };

export type Packet = {
  protocol: L3Protocol;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
};
