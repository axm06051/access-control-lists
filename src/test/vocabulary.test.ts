import { AudienceLevel } from '@/domains/acl/audience';
import {
  PROTOCOL_NAMES,
  ACTION_VERBS,
  ACTION_VERBS_LOWER,
  COMMUNICATION_TERMS,
  LAYER_DESCRIPTIONS,
  INSPECTION_TERMS,
  NETWORKING_TERMS,
} from '@/domains/acl/vocabulary';

describe('Vocabulary - Networking Terminology Graduation', () => {
  describe('NETWORKING_TERMS structure', () => {
    it('should have all required networking terms', () => {
      const requiredTerms = [
        'tcp',
        'udp',
        'icmp',
        'ospf',
        'http',
        'quic',
        'dns',
        'port',
        'segment',
        'sliding_window',
        'flow_control',
        'forward_acknowledgment',
        'error_detection',
        'error_recovery',
        'connection_establishment',
        'wildcard_mask',
        'access_control_entry',
        'named_access_list',
        'standard_access_list',
        'extended_access_list',
        'vty_acl',
        'web_server',
        'uri',
        'secure_http',
      ];

      requiredTerms.forEach((term) => {
        expect(NETWORKING_TERMS).toHaveProperty(term);
      });
    });

    it('should have all 5 audience levels for each term', () => {
      Object.entries(NETWORKING_TERMS).forEach(([term, levels]) => {
        expect(levels).toHaveProperty(AudienceLevel.Beginner.toString());
        expect(levels).toHaveProperty(AudienceLevel.Intermediate.toString());
        expect(levels).toHaveProperty(AudienceLevel.Advanced.toString());
        expect(levels).toHaveProperty(AudienceLevel.Expert.toString());
        expect(levels).toHaveProperty(AudienceLevel.Master.toString());
      });
    });
  });

  describe('Beginner level (A2 English)', () => {
    it('should use simple, concrete words (no acronyms)', () => {
      const beginnerTerms = Object.values(NETWORKING_TERMS).map(
        (levels) => levels[AudienceLevel.Beginner]
      );

      beginnerTerms.forEach((term) => {
        // No acronyms like TCP, UDP, ICMP, OSPF, HTTP, QUIC, DNS, TLS, RFC, IEEE, ISO
        expect(term).not.toMatch(/\b(TCP|UDP|ICMP|OSPF|HTTP|QUIC|DNS|TLS|RFC|IEEE|ISO)\b/);
        // Should be relatively short
        expect(term.split(' ').length).toBeLessThanOrEqual(5);
      });
    });

    it('TCP should use simple term', () => {
      expect(NETWORKING_TERMS['tcp']?.[AudienceLevel.Beginner]).toBe('reliable messenger');
    });

    it('UDP should use simple term', () => {
      expect(NETWORKING_TERMS['udp']?.[AudienceLevel.Beginner]).toBe('quick messenger');
    });

    it('ICMP should use simple term', () => {
      expect(NETWORKING_TERMS['icmp']?.[AudienceLevel.Beginner]).toBe('helper');
    });

    it('OSPF should use simple term', () => {
      expect(NETWORKING_TERMS['ospf']?.[AudienceLevel.Beginner]).toBe('path finder');
    });

    it('HTTP should use simple term', () => {
      expect(NETWORKING_TERMS['http']?.[AudienceLevel.Beginner]).toBe('web helper');
    });

    it('QUIC should use simple term', () => {
      expect(NETWORKING_TERMS['quic']?.[AudienceLevel.Beginner]).toBe('fast messenger');
    });

    it('DNS should use simple term', () => {
      expect(NETWORKING_TERMS['dns']?.[AudienceLevel.Beginner]).toBe('name finder');
    });

    it('port should use simple term', () => {
      expect(NETWORKING_TERMS['port']?.[AudienceLevel.Beginner]).toBe('door');
    });

    it('segment should use simple term', () => {
      expect(NETWORKING_TERMS['segment']?.[AudienceLevel.Beginner]).toBe('piece');
    });

    it('sliding_window should use simple term', () => {
      expect(NETWORKING_TERMS['sliding_window']?.[AudienceLevel.Beginner]).toBe('moving window');
    });

    it('flow_control should use simple term', () => {
      expect(NETWORKING_TERMS['flow_control']?.[AudienceLevel.Beginner]).toBe('speed control');
    });

    it('forward_acknowledgment should use simple term', () => {
      expect(NETWORKING_TERMS['forward_acknowledgment']?.[AudienceLevel.Beginner]).toBe('got it signal');
    });

    it('error_detection should use simple term', () => {
      expect(NETWORKING_TERMS['error_detection']?.[AudienceLevel.Beginner]).toBe('mistake finder');
    });

    it('error_recovery should use simple term', () => {
      expect(NETWORKING_TERMS['error_recovery']?.[AudienceLevel.Beginner]).toBe('mistake fixer');
    });

    it('connection_establishment should use simple term', () => {
      expect(NETWORKING_TERMS['connection_establishment']?.[AudienceLevel.Beginner]).toBe('handshake');
    });

    it('wildcard_mask should use simple term', () => {
      expect(NETWORKING_TERMS['wildcard_mask']?.[AudienceLevel.Beginner]).toBe('match pattern');
    });

    it('access_control_entry should use simple term', () => {
      expect(NETWORKING_TERMS['access_control_entry']?.[AudienceLevel.Beginner]).toBe('permission rule');
    });

    it('named_access_list should use simple term', () => {
      expect(NETWORKING_TERMS['named_access_list']?.[AudienceLevel.Beginner]).toBe('named rules');
    });

    it('standard_access_list should use simple term', () => {
      expect(NETWORKING_TERMS['standard_access_list']?.[AudienceLevel.Beginner]).toBe('basic rules');
    });

    it('extended_access_list should use simple term', () => {
      expect(NETWORKING_TERMS['extended_access_list']?.[AudienceLevel.Beginner]).toBe('detailed rules');
    });

    it('vty_acl should use simple term', () => {
      expect(NETWORKING_TERMS['vty_acl']?.[AudienceLevel.Beginner]).toBe('login rules');
    });

    it('web_server should use simple term', () => {
      expect(NETWORKING_TERMS['web_server']?.[AudienceLevel.Beginner]).toBe('web helper');
    });

    it('uri should use simple term', () => {
      expect(NETWORKING_TERMS['uri']?.[AudienceLevel.Beginner]).toBe('web address');
    });

    it('secure_http should use simple term', () => {
      expect(NETWORKING_TERMS['secure_http']?.[AudienceLevel.Beginner]).toBe('safe web');
    });
  });

  describe('Intermediate level (B1 English)', () => {
    it('should use basic technical terms without acronyms', () => {
      const intermediateTerms = Object.values(NETWORKING_TERMS).map(
        (levels) => levels[AudienceLevel.Intermediate]
      );

      intermediateTerms.forEach((term) => {
        // No acronyms
        expect(term).not.toMatch(/\b(TCP|UDP|ICMP|OSPF|HTTP|QUIC|DNS|TLS|RFC|IEEE|ISO)\b/);
      });
    });

    it('TCP should use basic technical term', () => {
      expect(NETWORKING_TERMS['tcp']?.[AudienceLevel.Intermediate]).toBe('reliable connection protocol');
    });

    it('UDP should use basic technical term', () => {
      expect(NETWORKING_TERMS['udp']?.[AudienceLevel.Intermediate]).toBe('fast delivery protocol');
    });

    it('ICMP should use basic technical term', () => {
      expect(NETWORKING_TERMS['icmp']?.[AudienceLevel.Intermediate]).toBe('network diagnostic protocol');
    });

    it('OSPF should use basic technical term', () => {
      expect(NETWORKING_TERMS['ospf']?.[AudienceLevel.Intermediate]).toBe('routing protocol');
    });

    it('HTTP should use basic technical term', () => {
      expect(NETWORKING_TERMS['http']?.[AudienceLevel.Intermediate]).toBe('web transfer protocol');
    });

    it('QUIC should use basic technical term', () => {
      expect(NETWORKING_TERMS['quic']?.[AudienceLevel.Intermediate]).toBe('fast transport protocol');
    });

    it('DNS should use basic technical term', () => {
      expect(NETWORKING_TERMS['dns']?.[AudienceLevel.Intermediate]).toBe('name resolution service');
    });

    it('port should use basic technical term', () => {
      expect(NETWORKING_TERMS['port']?.[AudienceLevel.Intermediate]).toBe('application endpoint');
    });

    it('segment should use basic technical term', () => {
      expect(NETWORKING_TERMS['segment']?.[AudienceLevel.Intermediate]).toBe('transport layer message');
    });

    it('sliding_window should use basic technical term', () => {
      expect(NETWORKING_TERMS['sliding_window']?.[AudienceLevel.Intermediate]).toBe('flow control mechanism');
    });

    it('flow_control should use basic technical term', () => {
      expect(NETWORKING_TERMS['flow_control']?.[AudienceLevel.Intermediate]).toBe('data rate regulation');
    });

    it('forward_acknowledgment should use basic technical term', () => {
      expect(NETWORKING_TERMS['forward_acknowledgment']?.[AudienceLevel.Intermediate]).toBe('receipt confirmation');
    });

    it('error_detection should use basic technical term', () => {
      expect(NETWORKING_TERMS['error_detection']?.[AudienceLevel.Intermediate]).toBe('corruption checking');
    });

    it('error_recovery should use basic technical term', () => {
      expect(NETWORKING_TERMS['error_recovery']?.[AudienceLevel.Intermediate]).toBe('retransmission process');
    });

    it('connection_establishment should use basic technical term', () => {
      expect(NETWORKING_TERMS['connection_establishment']?.[AudienceLevel.Intermediate]).toBe('three-way handshake');
    });

    it('wildcard_mask should use basic technical term', () => {
      expect(NETWORKING_TERMS['wildcard_mask']?.[AudienceLevel.Intermediate]).toBe('inverse network mask');
    });

    it('access_control_entry should use basic technical term', () => {
      expect(NETWORKING_TERMS['access_control_entry']?.[AudienceLevel.Intermediate]).toBe('access rule');
    });

    it('named_access_list should use basic technical term', () => {
      expect(NETWORKING_TERMS['named_access_list']?.[AudienceLevel.Intermediate]).toBe('named rule set');
    });

    it('standard_access_list should use basic technical term', () => {
      expect(NETWORKING_TERMS['standard_access_list']?.[AudienceLevel.Intermediate]).toBe('source-based filtering');
    });

    it('extended_access_list should use basic technical term', () => {
      expect(NETWORKING_TERMS['extended_access_list']?.[AudienceLevel.Intermediate]).toBe('advanced filtering');
    });

    it('vty_acl should use basic technical term', () => {
      expect(NETWORKING_TERMS['vty_acl']?.[AudienceLevel.Intermediate]).toBe('terminal access control');
    });

    it('web_server should use basic technical term', () => {
      expect(NETWORKING_TERMS['web_server']?.[AudienceLevel.Intermediate]).toBe('web content provider');
    });

    it('uri should use basic technical term', () => {
      expect(NETWORKING_TERMS['uri']?.[AudienceLevel.Intermediate]).toBe('resource locator');
    });

    it('secure_http should use basic technical term', () => {
      expect(NETWORKING_TERMS['secure_http']?.[AudienceLevel.Intermediate]).toBe('encrypted web protocol');
    });
  });

  describe('Advanced level (B2 English / CCNA Student)', () => {
    it('should use full technical names with acronyms in parentheses for protocols', () => {
      const protocolTerms = ['tcp', 'udp', 'icmp', 'ospf', 'http', 'quic', 'dns'];
      
      protocolTerms.forEach((term) => {
        const advancedTerm = NETWORKING_TERMS[term]?.[AudienceLevel.Advanced];
        // Protocol terms should contain acronyms in parentheses format
        expect(advancedTerm).toMatch(/\([A-Z]+\)/);
      });
    });

    it('TCP should use full name with acronym', () => {
      expect(NETWORKING_TERMS['tcp']?.[AudienceLevel.Advanced]).toBe('Transmission Control Protocol (TCP)');
    });

    it('UDP should use full name with acronym', () => {
      expect(NETWORKING_TERMS['udp']?.[AudienceLevel.Advanced]).toBe('User Datagram Protocol (UDP)');
    });

    it('ICMP should use full name with acronym', () => {
      expect(NETWORKING_TERMS['icmp']?.[AudienceLevel.Advanced]).toBe('Internet Control Message Protocol (ICMP)');
    });

    it('OSPF should use full name with acronym', () => {
      expect(NETWORKING_TERMS['ospf']?.[AudienceLevel.Advanced]).toBe('Open Shortest Path First (OSPF)');
    });

    it('HTTP should use full name with acronym', () => {
      expect(NETWORKING_TERMS['http']?.[AudienceLevel.Advanced]).toBe('Hypertext Transfer Protocol (HTTP)');
    });

    it('QUIC should use full name with acronym', () => {
      expect(NETWORKING_TERMS['quic']?.[AudienceLevel.Advanced]).toBe('Quick UDP Internet Connections (QUIC)');
    });

    it('DNS should use full name with acronym', () => {
      expect(NETWORKING_TERMS['dns']?.[AudienceLevel.Advanced]).toBe('Domain Name System (DNS)');
    });

    it('port should use technical definition', () => {
      expect(NETWORKING_TERMS['port']?.[AudienceLevel.Advanced]).toContain('port');
    });

    it('segment should use technical definition', () => {
      expect(NETWORKING_TERMS['segment']?.[AudienceLevel.Advanced]).toContain('segment');
    });

    it('sliding_window should use technical definition', () => {
      expect(NETWORKING_TERMS['sliding_window']?.[AudienceLevel.Advanced]).toContain('window');
    });

    it('flow_control should use technical definition', () => {
      expect(NETWORKING_TERMS['flow_control']?.[AudienceLevel.Advanced]).toContain('flow');
    });

    it('forward_acknowledgment should use technical definition', () => {
      expect(NETWORKING_TERMS['forward_acknowledgment']?.[AudienceLevel.Advanced]).toContain('acknowledgment');
    });

    it('error_detection should use technical definition', () => {
      expect(NETWORKING_TERMS['error_detection']?.[AudienceLevel.Advanced]).toContain('error');
    });

    it('error_recovery should use technical definition', () => {
      expect(NETWORKING_TERMS['error_recovery']?.[AudienceLevel.Advanced]).toContain('error');
    });

    it('connection_establishment should use technical definition', () => {
      expect(NETWORKING_TERMS['connection_establishment']?.[AudienceLevel.Advanced]).toContain('connection');
    });

    it('wildcard_mask should use technical definition', () => {
      expect(NETWORKING_TERMS['wildcard_mask']?.[AudienceLevel.Advanced]).toContain('wildcard');
    });

    it('access_control_entry should use technical definition', () => {
      expect(NETWORKING_TERMS['access_control_entry']?.[AudienceLevel.Advanced]).toContain('ACE');
    });

    it('named_access_list should use technical definition', () => {
      expect(NETWORKING_TERMS['named_access_list']?.[AudienceLevel.Advanced]).toContain('named');
    });

    it('standard_access_list should use technical definition', () => {
      expect(NETWORKING_TERMS['standard_access_list']?.[AudienceLevel.Advanced]).toContain('standard');
    });

    it('extended_access_list should use technical definition', () => {
      expect(NETWORKING_TERMS['extended_access_list']?.[AudienceLevel.Advanced]).toContain('extended');
    });

    it('vty_acl should use technical definition', () => {
      expect(NETWORKING_TERMS['vty_acl']?.[AudienceLevel.Advanced]).toContain('vty');
    });

    it('web_server should use technical definition', () => {
      expect(NETWORKING_TERMS['web_server']?.[AudienceLevel.Advanced]).toContain('server');
    });

    it('uri should use technical definition', () => {
      expect(NETWORKING_TERMS['uri']?.[AudienceLevel.Advanced]).toContain('URI');
    });

    it('secure_http should use technical definition', () => {
      expect(NETWORKING_TERMS['secure_http']?.[AudienceLevel.Advanced]).toContain('HTTPS');
    });
  });

  describe('Expert level (C1 English / Network Engineer)', () => {
    it('should use acronyms only', () => {
      const expertTerms = Object.values(NETWORKING_TERMS).map(
        (levels) => levels[AudienceLevel.Expert]
      );

      expertTerms.forEach((term) => {
        // Should be mostly acronyms or very short technical terms
        expect(term.length).toBeLessThanOrEqual(20);
      });
    });

    it('TCP should use acronym only', () => {
      expect(NETWORKING_TERMS['tcp']?.[AudienceLevel.Expert]).toBe('TCP');
    });

    it('UDP should use acronym only', () => {
      expect(NETWORKING_TERMS['udp']?.[AudienceLevel.Expert]).toBe('UDP');
    });

    it('ICMP should use acronym only', () => {
      expect(NETWORKING_TERMS['icmp']?.[AudienceLevel.Expert]).toBe('ICMP');
    });

    it('OSPF should use acronym only', () => {
      expect(NETWORKING_TERMS['ospf']?.[AudienceLevel.Expert]).toBe('OSPF');
    });

    it('HTTP should use acronym only', () => {
      expect(NETWORKING_TERMS['http']?.[AudienceLevel.Expert]).toBe('HTTP');
    });

    it('QUIC should use acronym only', () => {
      expect(NETWORKING_TERMS['quic']?.[AudienceLevel.Expert]).toBe('QUIC');
    });

    it('DNS should use acronym only', () => {
      expect(NETWORKING_TERMS['dns']?.[AudienceLevel.Expert]).toBe('DNS');
    });
  });

  describe('Master level (C2 English / Researcher)', () => {
    it('should use RFC/IEEE/ISO specifications', () => {
      const masterTerms = Object.values(NETWORKING_TERMS).map(
        (levels) => levels[AudienceLevel.Master]
      );

      masterTerms.forEach((term) => {
        // Should contain RFC, IEEE, or ISO references
        expect(term).toMatch(/RFC|IEEE|ISO/);
      });
    });

    it('TCP should reference RFC', () => {
      expect(NETWORKING_TERMS['tcp']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('UDP should reference RFC', () => {
      expect(NETWORKING_TERMS['udp']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('ICMP should reference RFC', () => {
      expect(NETWORKING_TERMS['icmp']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('OSPF should reference RFC', () => {
      expect(NETWORKING_TERMS['ospf']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('HTTP should reference RFC', () => {
      expect(NETWORKING_TERMS['http']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('QUIC should reference RFC', () => {
      expect(NETWORKING_TERMS['quic']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });

    it('DNS should reference RFC', () => {
      expect(NETWORKING_TERMS['dns']?.[AudienceLevel.Master]).toMatch(/RFC/);
    });
  });
});
