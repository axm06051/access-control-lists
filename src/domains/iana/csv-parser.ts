export function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (const char of line) {
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }

  result.push(current);
  return result;
}

export function cleanCSVValue(value: string | undefined): string {
  return value?.replace(/^"|"$/g, '').trim() || '';
}

export function parseHeaders(headerLine: string): Record<string, number> {
  const headers: Record<string, number> = {};
  parseCSVLine(headerLine).forEach((h, i) => {
    headers[cleanCSVValue(h)] = i;
  });
  return headers;
}
