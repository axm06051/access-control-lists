# ACL Study Tool

CCNA 200-301 Access Control Lists study tool with Cisco IOS-style CLI.

## Installation

Requires Node.js 18+ and pnpm.

```bash
git clone https://github.com/axm06051/access-control-lists.git
cd access-control-lists
pnpm install
```

## Running

```bash
pnpm dev
```

## Available Commands

- `learn <topic>` - Concept walkthrough for TCP/UDP, ports, standard ACLs, extended ACLs, placement, editing
- `drill <topic>` - Flashcard drills for wildcards, ports, ranges, operators, all topics
- `iana <cmd>` - IANA port registry search and lookup
- `topology` - View generated network topology
- `help` - Show command menu
- `exit` - Quit

## CLI Features

- Type `?` for context-sensitive help
- Tab completion for commands and arguments
- Partial command matching (e.g., `le` executes as `learn`)

## Testing

```bash
pnpm test
pnpm test:watch
pnpm test:coverage
```

## Building

```bash
pnpm build
```
