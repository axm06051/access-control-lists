import * as readline from 'node:readline';
import * as path from 'node:path';
import { Ansi } from '@/domains/acl';

const W = 66;

const COMMANDS = [
  { cmd: 'learn', desc: 'Concept walkthrough. "learn help" for topic list' },
  { cmd: 'drill', desc: 'Flashcard memorisation. "drill help" for topics' },
  { cmd: 'practice', desc: 'Guided lab 1–6. Omit n for menu' },
  { cmd: 'exam', desc: 'Timed CCNA-style mixed question session' },
  { cmd: 'answers', desc: 'Reveal full answer key (hidden by default)' },
  { cmd: 'topology', desc: 'Show this session\'s generated network topology' },
  { cmd: 'iana', desc: 'IANA port registry. "iana help" for commands' },
  { cmd: 'help', desc: 'Show this menu' },
  { cmd: 'exit', desc: 'Quit' },
];

export function section(title: string): void {
  console.log('\n' + Ansi.bold(Ansi.cyan(`── ${title} ${'─'.repeat(Math.max(0, W - 4 - title.length))}`)));
}

export function rule(): void {
  console.log(Ansi.cyan('─'.repeat(W)));
}

export function banner(title: string): void {
  const pad = Math.floor((W - title.length) / 2);
  const inner = ' '.repeat(pad) + title + ' '.repeat(W - pad - title.length);
  console.log(Ansi.bold(Ansi.cyan(`╔${'═'.repeat(W)}╗`)));
  console.log(Ansi.bold(Ansi.cyan(`║${inner}║`)));
  console.log(Ansi.bold(Ansi.cyan(`╚${'═'.repeat(W)}╝`)));
}

export async function pressEnter(rl: readline.Interface): Promise<void> {
  await ask(rl, Ansi.cyan('  [Enter to continue] '));
}

export function ask(rl: readline.Interface, prompt: string): Promise<string> {
  return new Promise((resolve) => rl.question(prompt, resolve));
}

export function handleQuestionMark(input: string): string | null {
  if (!input.endsWith('?')) return null;

  const partial = input.slice(0, -1).trim();
  const matches = COMMANDS.filter((c) => c.cmd.startsWith(partial));

  if (matches.length === 0) {
    console.log(Ansi.yellow('\n% Invalid command\n'));
    return null;
  }

  console.log();
  for (const m of matches) {
    console.log(`  ${Ansi.bold(m.cmd.padEnd(15))} ${m.desc}`);
  }
  console.log();

  if (matches.length === 1) {
    return matches[0]!.cmd;
  }

  return null;
}

export function getAutocompletions(partial: string): string[] {
  return COMMANDS.filter((c) => c.cmd.startsWith(partial.toLowerCase())).map((c) => c.cmd);
}

export function printHelp(): void {
  section('Commands');
  for (const { cmd, desc } of COMMANDS) {
    console.log(`  ${Ansi.bold(cmd.padEnd(18))} ${desc}`);
  }
  console.log();
}
