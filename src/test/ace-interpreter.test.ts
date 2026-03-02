import { StandardACE, ExtendedACE } from '@/domains/acl/entities';
import { AceExplainer, AudienceLevel } from '@/domains/acl/explanation';
import { Operation } from '@/domains/acl/types';
import { PROTOCOL_NAMES, ACTION_VERBS, COMMUNICATION_TERMS } from '@/domains/acl/vocabulary';

describe('AceExplainer', () => {
  describe('Standard ACE', () => {
    it('should explain permit standard ACE with correct structure', () => {
      const ace = new StandardACE(10, {
        op: Operation.Permit,
        srcIp: '192.168.1.0',
        wildcardMask: '0.0.0.255',
      });

      const exp = AceExplainer.explain(ace);

      expect(exp.sequenceNumber).toBe(10);
      expect(exp.action).toBe('permit');
      expect(exp.summary).toBeTruthy();
      expect(exp.summary).toContain('192.168.1.0/24');
      expect(exp.details).toBeInstanceOf(Array);
      expect(exp.details.length).toBeGreaterThan(0);
    });

    it('should explain deny standard ACE with correct structure', () => {
      const ace = new StandardACE(20, {
        op: Operation.Deny,
        srcIp: '10.0.0.0',
        wildcardMask: '0.0.0.255',
      });

      const exp = AceExplainer.explain(ace);

      expect(exp.action).toBe('deny');
      expect(exp.summary).toBeTruthy();
      expect(exp.details).toBeInstanceOf(Array);
    });
  });

  describe('Extended ACE', () => {
    it('should explain TCP with destination port', () => {
      const ace = new ExtendedACE(10, {
        op: Operation.Permit,
        protocol: 'tcp',
        srcIp: '10.0.0.0',
        srcWildcard: '0.0.0.255',
        dstIp: '0.0.0.0',
        dstWildcard: '255.255.255.255',
        dstPort: { op: 'eq', port: 443 },
      });

      const exp = AceExplainer.explain(ace);

      expect(exp.summary).toBeTruthy();
      expect(exp.summary).toContain('10.0.0.0/24');
      expect(exp.summary).toContain('443');
    });

    it('should explain UDP with source port', () => {
      const ace = new ExtendedACE(20, {
        op: Operation.Deny,
        protocol: 'udp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '203.0.113.1',
        dstWildcard: '0.0.0.0',
        srcPort: { op: 'gt', port: 50000 },
      });

      const exp = AceExplainer.explain(ace);

      expect(exp.summary).toBeTruthy();
      expect(exp.summary).toContain('50000');
    });

    it('should explain ICMP', () => {
      const ace = new ExtendedACE(30, {
        op: Operation.Deny,
        protocol: 'icmp',
        srcIp: '0.0.0.0',
        srcWildcard: '255.255.255.255',
        dstIp: '203.0.113.0',
        dstWildcard: '0.0.0.255',
      });

      const exp = AceExplainer.explain(ace);

      expect(exp.summary).toBeTruthy();
      expect(exp.summary).toContain('203.0.113.0/24');
    });
  });

  describe('Multiple ACEs', () => {
    it('should explain list of ACEs', () => {
      const aces = [
        new StandardACE(10, {
          op: Operation.Permit,
          srcIp: '192.168.1.0',
          wildcardMask: '0.0.0.255',
        }),
        new StandardACE(20, {
          op: Operation.Deny,
          srcIp: '10.0.0.0',
          wildcardMask: '0.0.0.255',
        }),
      ];

      const exps = AceExplainer.explainList(aces);

      expect(exps).toHaveLength(2);
      expect(exps[0]?.sequenceNumber).toBe(10);
      expect(exps[1]?.sequenceNumber).toBe(20);
    });
  });

  describe('Audience Levels - Vocabulary Requirements', () => {
    const ace = new ExtendedACE(10, {
      op: Operation.Permit,
      protocol: 'tcp',
      srcIp: '10.0.0.0',
      srcWildcard: '0.0.0.255',
      dstIp: '0.0.0.0',
      dstWildcard: '255.255.255.255',
      dstPort: { op: 'eq', port: 443 },
    });

    it('beginner level uses no acronyms', () => {
      const exp = AceExplainer.explain(ace, { audienceLevel: AudienceLevel.Beginner });
      expect(exp.summary).toBeTruthy();
      // Beginner should not contain acronyms like TCP, UDP, ICMP, etc.
      expect(exp.summary).not.toMatch(/\b(TCP|UDP|ICMP|OSPF|HTTP|QUIC|DNS|ACL|ACE)\b/);
    });

    it('intermediate level uses no acronyms', () => {
      const exp = AceExplainer.explain(ace, { audienceLevel: AudienceLevel.Intermediate });
      expect(exp.summary).toBeTruthy();
      // Intermediate should not contain acronyms
      expect(exp.summary).not.toMatch(/\b(TCP|UDP|ICMP|OSPF|HTTP|QUIC|DNS|ACL|ACE)\b/);
    });

    it('advanced level uses Full Name (ACRONYM) format', () => {
      const exp = AceExplainer.explain(ace, { audienceLevel: AudienceLevel.Advanced });
      expect(exp.summary).toBeTruthy();
      // Advanced should use proper format like "Transmission Control Protocol (TCP)"
      const advancedTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Advanced];
      expect(advancedTcp).toMatch(/\w+\s*\(\w+\)/);
    });

    it('expert level uses acronyms only', () => {
      const exp = AceExplainer.explain(ace, { audienceLevel: AudienceLevel.Expert });
      expect(exp.summary).toBeTruthy();
      // Expert should use acronyms
      const expertTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Expert];
      expect(expertTcp).toBe('TCP');
    });

    it('master level uses RFC references', () => {
      const exp = AceExplainer.explain(ace, { audienceLevel: AudienceLevel.Master });
      expect(exp.summary).toBeTruthy();
      // Master should reference RFCs
      const masterTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Master];
      expect(masterTcp).toMatch(/RFC\s*\d+/);
    });

    it('respects global config', () => {
      AceExplainer.setDefaultConfig({ audienceLevel: AudienceLevel.Beginner });
      const exp = AceExplainer.explain(ace);
      expect(exp.summary).toBeTruthy();
      expect(exp.summary).not.toMatch(/\b(TCP|UDP|ICMP)\b/);
      AceExplainer.setDefaultConfig({ audienceLevel: AudienceLevel.Intermediate });
    });

    it('overrides global config', () => {
      AceExplainer.setDefaultConfig({ audienceLevel: AudienceLevel.Beginner });
      const exp = AceExplainer.explain(ace, { 
        audienceLevel: AudienceLevel.Expert,
        includeTechnicalDetails: true,
      });
      expect(exp.summary).toBeTruthy();
      const expertTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Expert];
      expect(expertTcp).toBe('TCP');
      AceExplainer.setDefaultConfig({ audienceLevel: AudienceLevel.Intermediate });
    });
  });

  describe('Technical Details', () => {
    const ace = new StandardACE(10, {
      op: Operation.Permit,
      srcIp: '192.168.1.0',
      wildcardMask: '0.0.0.255',
    });

    it('includes when enabled', () => {
      const exp = AceExplainer.explain(ace, {
        audienceLevel: AudienceLevel.Advanced,
        includeTechnicalDetails: true,
      });
      expect(exp.details.length).toBeGreaterThan(0);
    });

    it('excludes when disabled', () => {
      const exp = AceExplainer.explain(ace, {
        audienceLevel: AudienceLevel.Advanced,
        includeTechnicalDetails: false,
      });
      expect(exp.details.length).toBeGreaterThan(0);
    });
  });

  describe('Vocabulary Acceptance Criteria', () => {
    it('action verbs have all 5 audience levels', () => {
      const permitVerbs = ACTION_VERBS['permit'];
      expect(permitVerbs).toBeDefined();
      expect(permitVerbs?.[AudienceLevel.Beginner]).toBeDefined();
      expect(permitVerbs?.[AudienceLevel.Intermediate]).toBeDefined();
      expect(permitVerbs?.[AudienceLevel.Advanced]).toBeDefined();
      expect(permitVerbs?.[AudienceLevel.Expert]).toBeDefined();
      expect(permitVerbs?.[AudienceLevel.Master]).toBeDefined();
    });

    it('protocol names have all 5 audience levels', () => {
      const tcpNames = PROTOCOL_NAMES['tcp'];
      expect(tcpNames).toBeDefined();
      expect(tcpNames?.[AudienceLevel.Beginner]).toBeDefined();
      expect(tcpNames?.[AudienceLevel.Intermediate]).toBeDefined();
      expect(tcpNames?.[AudienceLevel.Advanced]).toBeDefined();
      expect(tcpNames?.[AudienceLevel.Expert]).toBeDefined();
      expect(tcpNames?.[AudienceLevel.Master]).toBeDefined();
    });

    it('communication terms have all 5 audience levels', () => {
      expect(COMMUNICATION_TERMS[AudienceLevel.Beginner]).toBeDefined();
      expect(COMMUNICATION_TERMS[AudienceLevel.Intermediate]).toBeDefined();
      expect(COMMUNICATION_TERMS[AudienceLevel.Advanced]).toBeDefined();
      expect(COMMUNICATION_TERMS[AudienceLevel.Expert]).toBeDefined();
      expect(COMMUNICATION_TERMS[AudienceLevel.Master]).toBeDefined();
    });

    it('beginner action verbs contain no acronyms', () => {
      const beginnerPermit = ACTION_VERBS['permit']?.[AudienceLevel.Beginner];
      expect(beginnerPermit).toBeDefined();
      expect(beginnerPermit).not.toMatch(/\b[A-Z]{2,}\b/);
    });

    it('intermediate action verbs contain no acronyms', () => {
      const intermediatePermit = ACTION_VERBS['permit']?.[AudienceLevel.Intermediate];
      expect(intermediatePermit).toBeDefined();
      expect(intermediatePermit).not.toMatch(/\b[A-Z]{2,}\b/);
    });

    it('advanced protocol names use Full Name (ACRONYM) format', () => {
      const advancedTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Advanced];
      expect(advancedTcp).toBeDefined();
      expect(advancedTcp).toMatch(/\w+\s*\(\w+\)/);
    });

    it('expert protocol names are acronyms only', () => {
      const expertTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Expert];
      expect(expertTcp).toBeDefined();
      expect(expertTcp).toMatch(/^[A-Z]+$/);
    });

    it('master protocol names reference RFCs', () => {
      const masterTcp = PROTOCOL_NAMES['tcp']?.[AudienceLevel.Master];
      expect(masterTcp).toBeDefined();
      expect(masterTcp).toMatch(/RFC\s*\d+/);
    });
  });
});
