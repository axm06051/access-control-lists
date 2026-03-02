import { Glossary } from '@/domains/shared/glossary';

describe('Glossary', () => {
  describe('get', () => {
    it('retrieves definition by term', () => {
      const def = Glossary.get('ACL');
      expect(def).toBeDefined();
      expect(def).toContain('Access control list');
    });

    it('is case-insensitive', () => {
      const def1 = Glossary.get('ACL');
      const def2 = Glossary.get('acl');
      const def3 = Glossary.get('AcL');
      expect(def1).toBe(def2);
      expect(def2).toBe(def3);
    });

    it('returns undefined for unknown term', () => {
      const def = Glossary.get('UNKNOWN_TERM_XYZ');
      expect(def).toBeUndefined();
    });
  });

  describe('has', () => {
    it('checks if term exists', () => {
      expect(Glossary.has('TCP')).toBe(true);
      expect(Glossary.has('UDP')).toBe(true);
      expect(Glossary.has('UNKNOWN_XYZ')).toBe(false);
    });

    it('is case-insensitive', () => {
      expect(Glossary.has('tcp')).toBe(true);
      expect(Glossary.has('TCP')).toBe(true);
      expect(Glossary.has('TcP')).toBe(true);
    });
  });

  describe('search', () => {
    it('finds exact matches first', () => {
      const results = Glossary.search('TCP');
      expect(results[0]?.term).toBe('tcp');
      expect(results[0]?.similarity).toBe(1);
    });

    it('finds partial matches', () => {
      const results = Glossary.search('control');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0]?.similarity).toBeGreaterThan(0);
    });

    it('respects max results limit', () => {
      const results = Glossary.search('protocol', 3);
      expect(results.length).toBeLessThanOrEqual(3);
    });

    it('sorts by similarity descending', () => {
      const results = Glossary.search('access');
      for (let i = 1; i < results.length; i++) {
        expect(results[i - 1]!.similarity).toBeGreaterThanOrEqual(results[i]!.similarity);
      }
    });
  });

  describe('findRelated', () => {
    it('finds related terms by keyword overlap', () => {
      const results = Glossary.findRelated('TCP');
      expect(results.length).toBeGreaterThan(0);
    });

    it('excludes the search term itself', () => {
      const results = Glossary.findRelated('TCP');
      expect(results.every((r) => r.term !== 'tcp')).toBe(true);
    });

    it('respects max results limit', () => {
      const results = Glossary.findRelated('TCP', 2);
      expect(results.length).toBeLessThanOrEqual(2);
    });

    it('returns empty for unknown term', () => {
      const results = Glossary.findRelated('UNKNOWN_XYZ');
      expect(results).toEqual([]);
    });
  });

  describe('listAll', () => {
    it('returns all entries', () => {
      const entries = Glossary.listAll();
      expect(entries.length).toBeGreaterThan(0);
    });

    it('includes term and definition', () => {
      const entries = Glossary.listAll();
      expect(entries[0]).toHaveProperty('term');
      expect(entries[0]).toHaveProperty('definition');
    });
  });

  describe('common networking terms', () => {
    it('has ACL definition', () => {
      expect(Glossary.has('ACL')).toBe(true);
      expect(Glossary.get('ACL')).toContain('Access control list');
    });

    it('has TCP definition', () => {
      expect(Glossary.has('TCP')).toBe(true);
      expect(Glossary.get('TCP')).toContain('Transmission Control Protocol');
    });

    it('has UDP definition', () => {
      expect(Glossary.has('UDP')).toBe(true);
      expect(Glossary.get('UDP')).toContain('User Datagram Protocol');
    });

    it('has ICMP definition', () => {
      expect(Glossary.has('ICMP')).toBe(true);
      expect(Glossary.get('ICMP')).toContain('Internet Control Message Protocol');
    });

    it('has OSPF definition', () => {
      expect(Glossary.has('OSPF')).toBe(true);
      expect(Glossary.get('OSPF')).toContain('Open Shortest Path First');
    });
  });
});
