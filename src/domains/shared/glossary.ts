import * as fs from 'fs';
import * as path from 'path';

export interface GlossaryEntry {
  term: string;
  definition: string;
}

export interface GlossarySearchResult {
  term: string;
  definition: string;
  similarity: number;
}

export class Glossary {
  private static entries: Map<string, string> = new Map();
  private static initialized = false;

  static initialize(): void {
    if (this.initialized) return;

    try {
      const possiblePaths = [
        path.join(__dirname, '../../data/glossary.json'),
        path.join(__dirname, '../../../data/glossary.json'),
        path.join(process.cwd(), 'data/glossary.json'),
      ];

      let glossaryData: Record<string, string> | null = null;
      
      for (const glossaryPath of possiblePaths) {
        try {
          if (fs.existsSync(glossaryPath)) {
            glossaryData = JSON.parse(fs.readFileSync(glossaryPath, 'utf-8'));
            break;
          }
        } catch {
          // Continue to next path
        }
      }

      if (glossaryData) {
        Object.entries(glossaryData).forEach(([term, definition]) => {
          this.entries.set(term.toLowerCase(), definition);
        });
      }
    } catch (error) {
      console.warn('Failed to load glossary.json:', error);
    }

    this.initialized = true;
  }

  static get(term: string): string | undefined {
    this.initialize();
    return this.entries.get(term.toLowerCase());
  }

  static has(term: string): boolean {
    this.initialize();
    return this.entries.has(term.toLowerCase());
  }

  static search(query: string, maxResults: number = 5): GlossarySearchResult[] {
    this.initialize();
    const queryLower = query.toLowerCase();
    const results: GlossarySearchResult[] = [];

    this.entries.forEach((definition, term) => {
      const similarity = this.calculateSimilarity(queryLower, term);
      if (similarity > 0) {
        results.push({ term, definition, similarity });
      }
    });

    return results.sort((a, b) => b.similarity - a.similarity).slice(0, maxResults);
  }

  static findRelated(term: string, maxResults: number = 5): GlossarySearchResult[] {
    this.initialize();
    const definition = this.entries.get(term.toLowerCase());
    if (!definition) return [];

    const keywords = this.extractKeywords(definition);
    const results: GlossarySearchResult[] = [];

    this.entries.forEach((def, t) => {
      if (t === term.toLowerCase()) return;

      const defKeywords = this.extractKeywords(def);
      const commonKeywords = keywords.filter((k) => defKeywords.includes(k));
      const similarity = commonKeywords.length / Math.max(keywords.length, defKeywords.length);

      if (similarity > 0) {
        results.push({ term: t, definition: def, similarity });
      }
    });

    return results.sort((a, b) => b.similarity - a.similarity).slice(0, maxResults);
  }

  static listAll(): GlossaryEntry[] {
    this.initialize();
    return Array.from(this.entries.entries()).map(([term, definition]) => ({
      term,
      definition,
    }));
  }

  private static calculateSimilarity(query: string, term: string): number {
    if (term === query) return 1;
    if (term.includes(query)) return 0.8;
    if (query.includes(term)) return 0.6;

    const distance = this.levenshteinDistance(query, term);
    const maxLen = Math.max(query.length, term.length);
    return Math.max(0, 1 - distance / maxLen);
  }

  private static levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      const row = matrix[0];
      if (row) row[j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      const row = matrix[i];
      if (!row) continue;
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          const prevRow = matrix[i - 1];
          row[j] = prevRow?.[j - 1] ?? 0;
        } else {
          const prevRow = matrix[i - 1];
          const prevPrevVal = prevRow?.[j - 1] ?? 0;
          const prevVal = row[j - 1] ?? 0;
          const aboveVal = prevRow?.[j] ?? 0;
          row[j] = Math.min(prevPrevVal + 1, prevVal + 1, aboveVal + 1);
        }
      }
    }

    const lastRow = matrix[b.length];
    return lastRow?.[a.length] ?? 0;
  }

  private static extractKeywords(text: string): string[] {
    const stopWords = new Set(['a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'is', 'are', 'be', 'been', 'being']);
    return text
      .toLowerCase()
      .split(/\W+/)
      .filter((word) => word.length > 2 && !stopWords.has(word));
  }
}
