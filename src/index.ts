import { AccessList, Operation } from './types/acls';

// ─────────────────────────────────────────────────────────────────────────────
// All ACL examples from Chapter 23 of the CCNA book
// ─────────────────────────────────────────────────────────────────────────────

const acl = new AccessList();

// ── ACL 1  (Fig 23.1 / Fig 23.7 / Section 23.2.1) ───────────────────────────
// ACE 10  deny   192.168.1.0  0.0.0.255    ← block engineering dept
// ACE 20  permit 192.168.0.0  0.0.255.255  ← allow rest of 192.168.0.0/16
// Applied outbound on R2 G0/0 (protects Server LAN A)
acl.addStandardNumbered(1, Operation.Deny, '192.168.1.0', '0.0.0.255');
acl.addStandardNumbered(1, Operation.Permit, '192.168.0.0', '0.0.255.255');

// ── ACL 99 / BLOCK_MARTHA_BOB  (Section 23.2.2) ──────────────────────────────
// ACE 10  deny   192.168.1.11 0.0.0.0   ← block Martha (PC1, engineering)
// ACE 20  deny   192.168.2.17 0.0.0.0   ← block Bob    (PC2, accounting)
// ACE 30  permit 0.0.0.0     255.255.255.255  ← permit any
// Applied inbound on R2 G0/2
acl.addStandardNumbered(99, Operation.Deny, '192.168.1.11', '0.0.0.0');
acl.addStandardNumbered(99, Operation.Deny, '192.168.2.17', '0.0.0.0');
acl.addStandardNumbered(99, Operation.Permit, '0.0.0.0', '255.255.255.255');

// ── ACL 10  (Section 23.3 scenario — R2) ─────────────────────────────────────
// ACE 10  deny   192.168.2.0  0.0.0.255        ← block accounting dept
// ACE 20  permit 0.0.0.0     255.255.255.255   ← permit any
// Applied outbound on R2 G0/1 (protects Server LAN B)
acl.addStandardNumbered(10, Operation.Deny, '192.168.2.0', '0.0.0.255');
acl.addStandardNumbered(10, Operation.Permit, '0.0.0.0', '255.255.255.255');

// ── ACL 11 = BLOCK_ENGINEERING  (Section 23.3 scenario — R1) ─────────────────
// ACE 10  deny   192.168.1.0  0.0.0.255        ← block engineering
// ACE 20  permit 0.0.0.0     255.255.255.255   ← permit any
// Applied outbound on R1 G0/1 (prevents engineering → accounting)
acl.addStandardNumbered(11, Operation.Deny, '192.168.1.0', '0.0.0.255');
acl.addStandardNumbered(11, Operation.Permit, '0.0.0.0', '255.255.255.255');

// ── ACL 12 = BLOCK_ACCOUNTING  (Section 23.3 scenario — R1) ──────────────────
// ACE 10  deny   192.168.2.0  0.0.0.255        ← block accounting
// ACE 20  permit 0.0.0.0     255.255.255.255   ← permit any
// Applied outbound on R1 G0/0 (prevents accounting → engineering)
acl.addStandardNumbered(12, Operation.Deny, '192.168.2.0', '0.0.0.255');
acl.addStandardNumbered(12, Operation.Permit, '0.0.0.0', '255.255.255.255');

console.log(acl.toString());

// ─────────────────────────────────────────────────────────────────────────────
// Test runner — every packet example from the chapter figures
// ─────────────────────────────────────────────────────────────────────────────

type TestCase = {
  label: string;
  ip: string;
  aclId: number;
  expect: 'Permit' | 'Deny';
};

const tests: TestCase[] = [
  // ── ACL 1 ── outbound R2 G0/0 (Server LAN A) ─────────────────────────────
  {
    label: 'Fig 23.7 Pkt1 — Engineering host → Server LAN A',
    ip: '192.168.1.2',
    aclId: 1,
    expect: 'Deny',
  },
  {
    label: 'Fig 23.7 Pkt2 — Accounting host → Server LAN A',
    ip: '192.168.2.99',
    aclId: 1,
    expect: 'Permit',
  },
  {
    label: 'Fig 23.7 Pkt3 — Server LAN host → Server LAN A',
    ip: '192.168.3.10',
    aclId: 1,
    expect: 'Permit',
  },
  {
    label: 'Fig 23.3     — External host 172.16.1.1 (implicit deny)',
    ip: '172.16.1.1',
    aclId: 1,
    expect: 'Deny',
  },
  {
    label: 'Fig 23.1     — Engineering 192.168.1.1 matches deny ACE',
    ip: '192.168.1.1',
    aclId: 1,
    expect: 'Deny',
  },

  // ── ACL 99 / BLOCK_MARTHA_BOB ── inbound R2 G0/2 ─────────────────────────
  {
    label: 'Fig 23.8 Pkt1 — Martha 192.168.1.11',
    ip: '192.168.1.11',
    aclId: 99,
    expect: 'Deny',
  },
  {
    label: 'Fig 23.8 Pkt2 — Bob   192.168.2.17',
    ip: '192.168.2.17',
    aclId: 99,
    expect: 'Deny',
  },
  {
    label: 'Fig 23.8 Pkt3 — Other engineering host 192.168.1.2',
    ip: '192.168.1.2',
    aclId: 99,
    expect: 'Permit',
  },
  {
    label: 'Fig 23.8      — Other accounting host 192.168.2.5',
    ip: '192.168.2.5',
    aclId: 99,
    expect: 'Permit',
  },

  // ── ACL 10 — BLOCK_ACCOUNTING on R2 (Server LAN B) ───────────────────────
  {
    label: 'Sec 23.3 — Accounting host → Server LAN B',
    ip: '192.168.2.1',
    aclId: 10,
    expect: 'Deny',
  },
  {
    label: 'Sec 23.3 — Engineering host → Server LAN B',
    ip: '192.168.1.5',
    aclId: 10,
    expect: 'Permit',
  },

  // ── ACL 11 — BLOCK_ENGINEERING on R1 G0/1 ────────────────────────────────
  {
    label: 'Sec 23.3 — Engineering host → Accounting',
    ip: '192.168.1.10',
    aclId: 11,
    expect: 'Deny',
  },
  {
    label: 'Sec 23.3 — Accounting host passes BLOCK_ENGINEERING',
    ip: '192.168.2.10',
    aclId: 11,
    expect: 'Permit',
  },

  // ── ACL 12 — BLOCK_ACCOUNTING on R1 G0/0 ─────────────────────────────────
  {
    label: 'Sec 23.3 — Accounting host → Engineering',
    ip: '192.168.2.20',
    aclId: 12,
    expect: 'Deny',
  },
  {
    label: 'Sec 23.3 — Engineering host passes BLOCK_ACCOUNTING',
    ip: '192.168.1.20',
    aclId: 12,
    expect: 'Permit',
  },
];

let passed = 0;
let failed = 0;

console.log('═'.repeat(72));
console.log(' TEST RESULTS');
console.log('═'.repeat(72));

for (const { label, ip, aclId, expect } of tests) {
  const result = acl.validate(ip, aclId);
  const ok = result === expect;

  if (ok) passed++;
  else failed++;

  const status = ok ? '✓ PASS' : '✗ FAIL';
  console.log(`\n${status}  ACL ${aclId}  src=${ip}`);
  console.log(`       ${label}`);
  if (!ok) console.log(`       Expected: ${expect}   Got: ${result}`);
}

console.log('\n' + '═'.repeat(72));
console.log(` ${passed} passed, ${failed} failed out of ${tests.length} tests`);
console.log('═'.repeat(72) + '\n');
