import * as readline from 'node:readline';
import { Ansi } from '@/domains/acl';
import { banner, ask } from './commands';

interface DrillCard {
  id: string;
  question: string;
  answer: string;
}

export async function runDrill(topicArg: string, rl: readline.Interface, context: any): Promise<void> {
  const valid = ['wildcards', 'ports', 'ranges', 'operators', 'all'];
  let topic = topicArg.toLowerCase().trim();

  if (!topic) {
    console.log(Ansi.yellow('\n[!] Incomplete command. Choose a topic:\n'));
    for (const t of valid) console.log(`  ${t}`);
    return;
  }

  const matches = valid.filter((t) => t.startsWith(topic));
  if (matches.length === 1 && matches[0]) {
    topic = matches[0];
  } else if (matches.length === 0) {
    console.log(Ansi.yellow(`\nUnknown drill topic. Choose: ${valid.join(' | ')}`));
    return;
  }

  const cards = buildDrillDeck(topic, context);

  if (!cards.length) {
    console.log(Ansi.yellow('No cards for that topic.'));
    return;
  }

  banner(`Drill - ${topic}  (${cards.length} cards)`);
  console.log(Ansi.cyan('Type your answer + Enter. "skip" to reveal. "quit" to stop.\n'));

  let correct = 0;
  let skipped = 0;

  for (let i = 0; i < cards.length; i++) {
    const card = cards[i]!;
    const response = await ask(rl, `[${i + 1}/${cards.length}] ${card.question}\n> `);

    if (response.toLowerCase() === 'quit') break;
    if (response.toLowerCase() === 'skip') {
      console.log(Ansi.cyan(`Answer: ${card.answer}\n`));
      skipped++;
      continue;
    }

    const isCorrect = response.toLowerCase().trim() === card.answer.toLowerCase().trim();
    if (isCorrect) {
      console.log(Ansi.green('[+] Correct!\n'));
      correct++;
    } else {
      console.log(Ansi.red(`[-] Incorrect. Answer: ${card.answer}\n`));
    }
  }

  const total = cards.length - skipped;
  const pct = total > 0 ? Math.round((correct / total) * 100) : 0;
  console.log(Ansi.cyan(`\nScore: ${correct}/${total} (${pct}%)\n`));
}

function buildDrillDeck(topic: string, context: any): DrillCard[] {
  const cards: DrillCard[] = [];
  const { PORT_TABLE, IANA_TIERS, prefixToWildcard, ANSWER_KEY } = context;

  if (topic === 'wildcards' || topic === 'all') {
    const prefixes = [8, 16, 20, 24, 25, 27, 28, 30];
    prefixes.forEach((p, i) => {
      const wc = prefixToWildcard(p);
      cards.push({
        id: `D-WC-${i + 1}`,
        question: `Wildcard mask for /${p}?`,
        answer: wc,
      });
    });
  }

  if (topic === 'ports' || topic === 'all') {
    PORT_TABLE.forEach((row: any, i: number) => {
      cards.push({
        id: `D-PORT-${i + 1}`,
        question: `Port number for ${row.name} (${row.transport})?`,
        answer: String(row.port),
      });
    });
  }

  if (topic === 'ranges' || topic === 'all') {
    let ri = 1;
    for (const t of IANA_TIERS) {
      cards.push({
        id: `D-IANA-${ri++}`,
        question: `Port range for IANA "${t.label}" tier?`,
        answer: `${t.start}–${t.stop} (${t.alias})`,
      });
    }
  }

  if (topic === 'operators' || topic === 'all') {
    const opCases: [string, string][] = [
      ['eq 443', 'equal to 443'],
      ['gt 1023', 'greater than 1023 (not including 1023)'],
      ['lt 1024', 'less than 1024 (not including 1024)'],
      ['neq 23', 'not equal to 23'],
      ['range 80 100', '80 to 100 inclusive'],
    ];
    opCases.forEach(([op, meaning], i) => {
      cards.push({
        id: `D-OP-${i + 1}`,
        question: `What does ACE port operator "${op}" match?`,
        answer: meaning,
      });
    });
  }

  return cards;
}
