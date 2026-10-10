import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import ssh2 from 'ssh2';
const sshUtils = ssh2.utils;
import { Sealer, hashPassword, verifyPassword } from './lib/crypto.js';
import { openDb } from './db.js';
import { audit, verifyAuditChain } from './lib/audit.js';
import { summarize, sshPortsFrom, parseSections } from './preflight.js';
import { bootstrapSnippet } from './bootstrap.js';
import { buildInstallScript, readKitFile } from './nodekit.js';
import { fingerprintOf, mask, withNodeLock } from './ssh/executor.js';

test('sealer roundtrip and tamper detection', () => {
  const s = new Sealer(Buffer.alloc(32, 7));
  const sealed = s.seal('secret-key');
  assert.equal(s.open(sealed).toString(), 'secret-key');
  const bad = sealed.slice(0, -4) + (sealed.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  assert.throws(() => s.open(bad));
});

test('password hashing', () => {
  const h = hashPassword('correct horse battery');
  assert.ok(verifyPassword('correct horse battery', h));
  assert.ok(!verifyPassword('wrong', h));
});

test('audit hash chain detects tampering', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-'));
  const db = openDb(dir);
  audit(db, 'a', 'x');
  audit(db, 'a', 'y', 't', { k: 1 });
  assert.deepEqual(verifyAuditChain(db), { ok: true });
  db.prepare(`UPDATE audit_log SET action = 'z' WHERE id = 1`).run();
  assert.equal(verifyAuditChain(db).ok, false);
  db.close();
});

const RAW = `
### os
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu

### kernel
6.8.0-45-generic
x86_64

### whoami
uid=0(root) gid=0(root) groups=0(root)

### ssh_connection
198.51.100.9 51022 203.0.113.50 3333

### sshd_t
port 3333
permitrootlogin yes
passwordauthentication yes
usepam yes

### ssh_socket
Listen=[::]:3333 (Stream) 0.0.0.0:3333 (Stream)
ActiveState=active
ssh.service=active

### listen
tcp   LISTEN 0      4096         0.0.0.0:3333      0.0.0.0:*    users:(("sshd",pid=900,fd=3),("systemd",pid=1,fd=200))
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1000,fd=6))

### ufw
Status: active

### nft
table inet filter {
}

### iptables
-A INPUT -j ufw-before-input

### docker
none

### dpkg_audit

### dpkg_lock
free

### unattended
active

### disk
/dev/vda1 20000000 5000000 15000000 25% /

### mem
1963 1500

### time
NTPSynchronized=yes
Timezone=Europe/Warsaw

### ipv4
2: eth0    inet 203.0.113.50/24 scope global eth0

### ipv6

route:

### python3
/usr/bin/python3
`;

test('preflight parsing', () => {
  const s = parseSections(RAW);
  assert.deepEqual(sshPortsFrom(s), [3333]);
  const sum = summarize(RAW, ['203.0.113.5']);
  const by = Object.fromEntries(sum.checks.map((c) => [c.id, c]));
  assert.equal(by.os!.status, 'ok');
  assert.equal(by.sudo!.status, 'ok');
  assert.equal(by.ufw!.status, 'warn');
  assert.equal(by.egress!.status, 'warn'); // 198.51.100.9 not in executor list
  assert.equal(by.ports!.status, 'warn'); // nginx on 80
  assert.equal(by.time!.status, 'ok');
  assert.equal(sum.clientIp, '198.51.100.9');
  assert.equal(sum.ufwActive, true);
  assert.equal(sum.blocking, false);
});

function bashSyntax(script: string) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-sh-')), 's.sh');
  fs.writeFileSync(f, script);
  execFileSync('bash', ['-n', f]);
}

test('bootstrap snippet is valid bash and contains from= list', () => {
  const k = sshUtils.generateKeyPairSync('ed25519', { comment: 'fleet-panel/srv-test' });
  const snip = bootstrapSnippet({ panelIps: ['203.0.113.5', '2001:db8::1'], pubkey: k.public.trim() });
  bashSyntax(snip);
  assert.match(snip, /PANEL_IPS="203\.0\.113\.5,2001:db8::1"/);
  assert.match(snip, /fleet-panel\/srv-test/);
});

test('nodekit scripts and installer are valid bash', () => {
  for (const f of ['fleet-exec', 'fleetctl', 'fleet-preflight', 'fleet-baseline', 'fleet-fw-apply', 'fleet-fw-rollback', 'fleet-fw-confirm'])
    bashSyntax(readKitFile(`sbin/${f}`));
  const inst = buildInstallScript();
  bashSyntax(inst);
  assert.ok(!inst.includes('\r'));
});

test('fingerprint format matches ssh-keygen (SHA256, no padding)', () => {
  const k = sshUtils.generateKeyPairSync('ed25519');
  const blob = Buffer.from(k.public.split(' ')[1]!, 'base64');
  const { fp, algo } = fingerprintOf(blob);
  assert.equal(algo, 'ssh-ed25519');
  assert.match(fp, /^SHA256:[A-Za-z0-9+/]{43}$/);
});

test('mask hides secrets', () => {
  assert.equal(mask('key=abcdef123 ok', ['abcdef123']), 'key=*** ok');
});

test('node lock serializes operations per node', async () => {
  const order: string[] = [];
  const slow = (tag: string, ms: number) =>
    withNodeLock('n1', async () => {
      order.push(`${tag}+`);
      await new Promise((r) => setTimeout(r, ms));
      order.push(`${tag}-`);
    });
  await Promise.all([slow('a', 30), slow('b', 1), withNodeLock('n2', async () => void order.push('c'))]);
  assert.deepEqual(order.filter((x) => x !== 'c'), ['a+', 'a-', 'b+', 'b-']);
});
