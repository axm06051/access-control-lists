import { AccessControlEntry, StandardACE, ExtendedACE } from './entities';
import { L3Protocol, PortCondition } from './types';
import { operationName } from '../shared/utils';
import { PortMatcher } from '../shared/services';
import { AudienceLevel } from './audience';
import { PROTOCOL_NAMES, ACTION_VERBS, ACTION_VERBS_LOWER, COMMUNICATION_TERMS, LAYER_DESCRIPTIONS, INSPECTION_TERMS } from './vocabulary';

export { AudienceLevel };

export interface AceExplanation {
  sequenceNumber: number;
  action: string;
  summary: string;
  details: string[];
}

export interface ExplanationConfig {
  audienceLevel: AudienceLevel;
  includeTechnicalDetails?: boolean;
}

export class AceExplainer {
  private static defaultConfig: ExplanationConfig = {
    audienceLevel: AudienceLevel.Intermediate,
    includeTechnicalDetails: true,
  };

  static setDefaultConfig(config: Partial<ExplanationConfig>): void {
    this.defaultConfig = { ...this.defaultConfig, ...config };
  }

  static explain(ace: AccessControlEntry, config?: Partial<ExplanationConfig>): AceExplanation {
    const finalConfig = { ...this.defaultConfig, ...config };

    if (ace instanceof StandardACE) {
      return this.explainStandard(ace, finalConfig);
    }
    if (ace instanceof ExtendedACE) {
      return this.explainExtended(ace, finalConfig);
    }
    throw new Error('Unknown access control entry type');
  }

  static explainList(aces: AccessControlEntry[], config?: Partial<ExplanationConfig>): AceExplanation[] {
    return aces.map((ace) => this.explain(ace, config));
  }

  private static explainStandard(ace: StandardACE, config: ExplanationConfig): AceExplanation {
    const action = operationName(ace.operation).toLowerCase();
    const aceStr = ace.toString();
    const parts = aceStr.trim().split(/\s+/);
    const srcIp = parts[2] ?? '';
    const wildcard = parts[3] ?? '';

    return {
      sequenceNumber: ace.sequenceNumber,
      action,
      summary: this.summarizeStandard(action, srcIp, wildcard, config),
      details: this.detailStandard(action, srcIp, wildcard, config),
    };
  }

  private static explainExtended(ace: ExtendedACE, config: ExplanationConfig): AceExplanation {
    const action = operationName(ace.operation).toLowerCase();
    const aceStr = ace.toString();
    const parts = aceStr.trim().split(/\s+/);

    const protocol: L3Protocol = (parts[2] ?? 'ip') as L3Protocol;
    const srcIp: string = parts[3] ?? 'any';
    const srcWildcard: string = parts[4] ?? 'any';

    let dstIdx = 5;
    let srcPort: PortCondition | undefined;
    let dstIp: string = 'any';
    let dstWildcard: string = 'any';
    let dstPort: PortCondition | undefined;

    if (this.isPortOp(parts[5])) {
      srcPort = this.parsePort(parts, 5);
      dstIdx = this.nextIdx(parts, 5);
    }

    dstIp = parts[dstIdx] ?? 'any';
    dstWildcard = parts[dstIdx + 1] ?? 'any';

    if (dstIdx + 2 < parts.length && this.isPortOp(parts[dstIdx + 2])) {
      dstPort = this.parsePort(parts, dstIdx + 2);
    }

    const summary = this.summarizeExtended(action, protocol, srcIp, srcWildcard, srcPort, dstIp, dstWildcard, dstPort, config);
    const details = this.detailExtended(action, protocol, srcIp, srcWildcard, srcPort, dstIp, dstWildcard, dstPort, config);

    return { sequenceNumber: ace.sequenceNumber, action, summary, details };
  }

  private static summarizeStandard(action: string, srcIp: string, wildcard: string, config: ExplanationConfig): string {
    const network = this.formatNetwork(srcIp, wildcard);
    const verb = this.actionVerb(action, config.audienceLevel);

    switch (config.audienceLevel) {
      case AudienceLevel.Beginner:
        return `${verb} all communications from ${network}`;
      case AudienceLevel.Intermediate:
        return `${verb} all network traffic from ${network}`;
      default:
        return `${verb} all network datagrams originating from ${network}`;
    }
  }

  private static detailStandard(action: string, srcIp: string, wildcard: string, config: ExplanationConfig): string[] {
    const network = this.formatNetwork(srcIp, wildcard);
    const verb = this.actionVerbLower(action, config.audienceLevel);
    const details: string[] = [];

    switch (config.audienceLevel) {
      case AudienceLevel.Beginner:
        details.push(`This rule ${verb} all communications coming from ${network}.`);
        details.push(`It only examines where communications originate.`);
        details.push(`It does not consider the type of communication or its destination.`);
        break;

      case AudienceLevel.Intermediate:
        details.push(`This rule ${verb} all network traffic originating from ${network}.`);
        details.push(`Access control lists examine only the source address.`);
        details.push(`All communication types, ports, and destinations are included.`);
        break;

      case AudienceLevel.Advanced:
        details.push(`This rule ${verb} network datagrams with source address matching ${network}.`);
        details.push(`Source-only filtering at the network layer without transport layer inspection.`);
        details.push(`No examination of communication protocols or port numbers.`);
        if (config.includeTechnicalDetails) {
          details.push(`Wildcard mask: ${wildcard} (inverse of network mask)`);
        }
        break;

      case AudienceLevel.Expert:
        details.push(`This rule ${verb} network datagrams where source address matches ${network}.`);
        details.push(`Network layer filtering with source-only matching semantics.`);
        details.push(`No transport layer inspection; all protocols and port ranges implicitly matched.`);
        if (config.includeTechnicalDetails) {
          details.push(`Wildcard mask: ${wildcard} (bitwise inverse of network mask)`);
          details.push(`Processing: Sequential evaluation with first-match semantics; implicit deny at end.`);
        }
        break;

      case AudienceLevel.Master:
        details.push(`This rule ${verb} network datagrams satisfying source address matching criteria.`);
        details.push(`Network layer filtering with source-only discrimination.`);
        details.push(`Stateless, unidirectional filtering without transport layer awareness or flow state tracking.`);
        if (config.includeTechnicalDetails) {
          details.push(`Wildcard mask: ${wildcard} (bitwise complement of network mask)`);
          details.push(`Evaluation semantics: Sequential, first-match-wins with implicit deny rule.`);
          details.push(`Performance characteristics: O(n) lookup with no caching or optimization.`);
        }
        break;
    }

    return details;
  }

  private static summarizeExtended(
    action: string,
    protocol: L3Protocol,
    srcIp: string,
    srcWildcard: string,
    srcPort: PortCondition | undefined,
    dstIp: string,
    dstWildcard: string,
    dstPort: PortCondition | undefined,
    config: ExplanationConfig
  ): string {
    const srcNet = this.formatNetwork(srcIp, srcWildcard);
    const dstNet = this.formatNetwork(dstIp, dstWildcard);
    const proto = this.protocolName(protocol, config.audienceLevel);
    const verb = this.actionVerb(action, config.audienceLevel);
    const commTerm = this.getCommunicationTerm(config.audienceLevel, 0);

    if (config.audienceLevel === AudienceLevel.Beginner) {
      let summary = `${verb} ${proto} ${commTerm} from ${srcNet}`;
      if (srcPort) summary += ` (from port ${this.portStr(srcPort)})`;
      summary += ` to ${dstNet}`;
      if (dstPort) summary += ` (to port ${this.portStr(dstPort)})`;
      return summary;
    }

    let extSummary = `${verb} ${proto} ${commTerm} from ${srcNet}`;
    if (srcPort) extSummary += ` with source port ${this.portStr(srcPort)}`;
    extSummary += ` to ${dstNet}`;
    if (dstPort) extSummary += ` on port ${this.portStr(dstPort)}`;
    return extSummary;
  }

  private static detailExtended(
    action: string,
    protocol: L3Protocol,
    srcIp: string,
    srcWildcard: string,
    srcPort: PortCondition | undefined,
    dstIp: string,
    dstWildcard: string,
    dstPort: PortCondition | undefined,
    config: ExplanationConfig
  ): string[] {
    const details: string[] = [];
    const srcNet = this.formatNetwork(srcIp, srcWildcard);
    const dstNet = this.formatNetwork(dstIp, dstWildcard);
    const proto = this.protocolName(protocol, config.audienceLevel);
    const verb = this.actionVerbLower(action, config.audienceLevel);

    switch (config.audienceLevel) {
      case AudienceLevel.Beginner:
        details.push(`This rule ${verb} ${proto} communications.`);
        details.push(`From: ${srcNet}${srcPort ? ` (port ${this.portStr(srcPort)})` : ''}`);
        details.push(`To: ${dstNet}${dstPort ? ` (port ${this.portStr(dstPort)})` : ''}`);
        break;

      case AudienceLevel.Intermediate:
        details.push(`This rule ${verb} ${proto} communications.`);
        details.push(`Source: ${srcNet}${srcPort ? ` (port ${this.portStr(srcPort)})` : ''}`);
        details.push(`Destination: ${dstNet}${dstPort ? ` (port ${this.portStr(dstPort)})` : ''}`);
        break;

      case AudienceLevel.Advanced:
        details.push(`This rule ${verb} ${proto} datagrams matching all specified criteria.`);
        details.push(`Source: ${srcNet}${srcPort ? ` (port ${this.portStr(srcPort)})` : ''}`);
        details.push(`Destination: ${dstNet}${dstPort ? ` (port ${this.portStr(dstPort)})` : ''}`);
        details.push(`Protocol: ${proto} (network layer filtering)`);
        if (config.includeTechnicalDetails) {
          details.push(`Matching: All conditions must be satisfied (conjunction logic)`);
        }
        break;

      case AudienceLevel.Expert:
        details.push(`This rule ${verb} ${proto} datagrams satisfying all matching criteria.`);
        details.push(`Source: ${srcNet}${srcPort ? ` (port ${this.portStr(srcPort)})` : ''}`);
        details.push(`Destination: ${dstNet}${dstPort ? ` (port ${this.portStr(dstPort)})` : ''}`);
        details.push(`Protocol: ${proto} (network layer filtering)`);
        if (config.includeTechnicalDetails) {
          details.push(`Semantics: Conjunctive evaluation of all specified conditions`);
          details.push(`Implicit deny: Datagrams not matching any rule are discarded`);
        }
        break;

      case AudienceLevel.Master:
        details.push(`This rule ${verb} ${proto} datagrams satisfying all specified matching criteria.`);
        details.push(`Source: ${srcNet}${srcPort ? ` (port ${this.portStr(srcPort)})` : ''}`);
        details.push(`Destination: ${dstNet}${dstPort ? ` (port ${this.portStr(dstPort)})` : ''}`);
        details.push(`Protocol: ${proto} (network layer filtering)`);
        if (config.includeTechnicalDetails) {
          details.push(`Matching semantics: Conjunctive evaluation; first-match-wins processing`);
          details.push(`Implicit deny: Datagrams not matching any rule are discarded (default-deny policy)`);
          details.push(`Performance: O(n) sequential evaluation; no caching or optimization`);
          details.push(`Stateless: No connection state tracking; bidirectional rules required for symmetric policies`);
        }
        break;
    }

    return details;
  }

  private static getActionVerb(action: string, level: AudienceLevel): string {
    if (level === AudienceLevel.Beginner) {
      return action === 'permit' ? 'Allows' : 'Blocks';
    }
    return action === 'permit' ? 'Permits' : 'Denies';
  }

  private static actionVerb(action: string, level: AudienceLevel): string {
    return ACTION_VERBS[action]?.[level] ?? 'Permits';
  }

  private static actionVerbLower(action: string, level: AudienceLevel): string {
    return ACTION_VERBS_LOWER[action]?.[level] ?? 'permits';
  }

  private static formatNetwork(ip: string, wildcard: string): string {
    if (ip === 'any' || wildcard === 'any') return 'any host';
    if (ip === 'host' || ip.startsWith('host ')) {
      const hostIp = ip.startsWith('host ') ? ip.substring(5) : wildcard;
      return `host ${hostIp}`;
    }
    const cidr = this.wildcardToCidr(wildcard);
    return `${ip}/${cidr}`;
  }

  private static wildcardToCidr(wildcard: string): number {
    if (wildcard === '0.0.0.0') return 32;
    if (wildcard === '0.0.0.255') return 24;
    if (wildcard === '0.0.255.255') return 16;
    if (wildcard === '0.255.255.255') return 8;
    if (wildcard === '255.255.255.255') return 0;

    const octets = wildcard.split('.').map(Number);
    let bits = 0;
    for (const octet of octets) {
      bits += 8 - this.popcount(octet);
    }
    return bits;
  }

  private static popcount(n: number): number {
    let count = 0;
    for (let i = 0; i < 8; i++) {
      if ((n & (1 << i)) !== 0) count++;
    }
    return count;
  }

  private static protocolName(protocol: L3Protocol, level: AudienceLevel): string {
    return PROTOCOL_NAMES[protocol]?.[level] ?? protocol;
  }

  private static portStr(condition: PortCondition): string {
    if (condition.op === 'range') return `${condition.portA}-${condition.portB}`;
    const matcher = new PortMatcher(condition);
    return matcher.toString();
  }

  private static parsePort(parts: string[], idx: number): PortCondition | undefined {
    const op = parts[idx];
    if (!op) return undefined;
    const next = parts[idx + 1];
    const nextNext = parts[idx + 2];
    if (op === 'range' && next && nextNext) {
      return { op: 'range', portA: parseInt(next, 10), portB: parseInt(nextNext, 10) };
    }
    if (next) {
      return { op: op as Exclude<string, 'range'>, port: parseInt(next, 10) } as PortCondition;
    }
    return undefined;
  }

  private static nextIdx(parts: string[], idx: number): number {
    const op = parts[idx];
    if (op === 'range' && parts[idx + 1] && parts[idx + 2]) return idx + 3;
    return idx + 2;
  }

  private static isPortOp(str: string | undefined): boolean {
    return str ? ['eq', 'gt', 'lt', 'neq', 'range'].includes(str) : false;
  }

  private static getCommunicationTerm(level: AudienceLevel, index: number): string {
    const terms = COMMUNICATION_TERMS[level];
    return terms[index % terms.length] ?? 'communications';
  }
}
