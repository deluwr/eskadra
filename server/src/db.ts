import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';

const MIGRATIONS: string[] = [
  `
  CREATE TABLE admins (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
  CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    ssh_user TEXT NOT NULL DEFAULT 'fleet',
    role TEXT NOT NULL DEFAULT 'entry',
    status TEXT NOT NULL DEFAULT 'pending_bootstrap',
    key_pub TEXT NOT NULL,
    key_priv_sealed TEXT NOT NULL,
    host_key_fp TEXT,
    host_key_pending_fp TEXT,
    host_key_algo TEXT,
    sudo_mode TEXT NOT NULL DEFAULT 'bootstrap',
    protection_target TEXT NOT NULL DEFAULT 'P3',
    fw_mode TEXT NOT NULL DEFAULT 'observe',
    seen_from_ip TEXT,
    os_info TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE preflight_reports (
    id INTEGER PRIMARY KEY,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    summary TEXT NOT NULL,
    raw TEXT NOT NULL
  );
  CREATE TABLE jobs (
    id INTEGER PRIMARY KEY,
    server_id TEXT REFERENCES servers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    log TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
  );
  CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    prev_hash TEXT,
    hash TEXT NOT NULL
  );
  `,
  `
  ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'owner';
  ALTER TABLE admins ADD COLUMN totp_sealed TEXT;
  ALTER TABLE admins ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE admins ADD COLUMN tg_id TEXT;
  ALTER TABLE admins ADD COLUMN backup_recipient INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE admins ADD COLUMN last_login_at TEXT;
  ALTER TABLE sessions ADD COLUMN ip TEXT;

  ALTER TABLE servers ADD COLUMN group_name TEXT NOT NULL DEFAULT 'default';
  ALTER TABLE servers ADD COLUMN direct_access INTEGER NOT NULL DEFAULT 1;
  ALTER TABLE servers ADD COLUMN peer_ssh TEXT NOT NULL DEFAULT 'off';
  ALTER TABLE servers ADD COLUMN ssh_mode TEXT NOT NULL DEFAULT 'loose';
  ALTER TABLE servers ADD COLUMN ssh_ports TEXT;
  ALTER TABLE servers ADD COLUMN protection_current TEXT NOT NULL DEFAULT 'P1';
  ALTER TABLE servers ADD COLUMN key_only INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE servers ADD COLUMN ufw_active INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE servers ADD COLUMN checklist TEXT NOT NULL DEFAULT '{}';
  ALTER TABLE servers ADD COLUMN checklist_passed_at TEXT;
  ALTER TABLE servers ADD COLUMN fail_since TEXT;
  ALTER TABLE servers ADD COLUMN cores TEXT NOT NULL DEFAULT '{}';
  ALTER TABLE servers ADD COLUMN fw_plan TEXT;
  ALTER TABLE servers ADD COLUMN fw_plan_hash TEXT;
  ALTER TABLE servers ADD COLUMN fw_pending_until TEXT;
  ALTER TABLE servers ADD COLUMN admin_ips TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE servers ADD COLUMN kit_version TEXT;

  CREATE TABLE groups (
    name TEXT PRIMARY KEY,
    stealth TEXT NOT NULL DEFAULT 'S0',
    peer_scope TEXT NOT NULL DEFAULT 'services',
    port_range TEXT NOT NULL DEFAULT '443,1024-65535'
  );
  INSERT INTO groups (name) VALUES ('default');

  CREATE TABLE templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    core TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    sni TEXT NOT NULL DEFAULT '[]',
    fingerprint TEXT NOT NULL DEFAULT 'chrome',
    ech INTEGER NOT NULL DEFAULT 0,
    node_ids TEXT NOT NULL DEFAULT '[]',
    entry_id TEXT,
    entry_port INTEGER,
    revision INTEGER NOT NULL DEFAULT 1,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE inbounds (
    id TEXT PRIMARY KEY,
    template_id TEXT NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    private_key_sealed TEXT,
    public_key TEXT,
    short_id TEXT,
    tls_pin TEXT,
    error TEXT,
    applied_at TEXT,
    UNIQUE (template_id, server_id, kind)
  );

  CREATE TABLE limit_groups (
    name TEXT PRIMARY KEY,
    traffic_gb REAL,
    days INTEGER,
    devices INTEGER
  );
  INSERT INTO limit_groups (name, traffic_gb, days, devices) VALUES ('default', NULL, NULL, 3);

  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    tg_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    limit_group TEXT NOT NULL DEFAULT 'default',
    traffic_limit_gb REAL,
    expire_at TEXT,
    device_limit INTEGER,
    over_action TEXT NOT NULL DEFAULT 'disable',
    modes TEXT NOT NULL DEFAULT '["direct","via"]',
    node_ids TEXT,
    wl_mode TEXT NOT NULL DEFAULT 'exact',
    sub_token TEXT NOT NULL UNIQUE,
    knock_token TEXT NOT NULL UNIQUE,
    disabled_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE user_creds (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    secret_sealed TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
  );

  CREATE TABLE service_creds (
    key TEXT PRIMARY KEY,
    secret_sealed TEXT NOT NULL
  );

  CREATE TABLE traffic (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    up INTEGER NOT NULL DEFAULT 0,
    down INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, period)
  );

  CREATE TABLE allowed_ips (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    source TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, cidr)
  );

  CREATE TABLE peer_checks (
    from_id TEXT NOT NULL,
    to_id TEXT NOT NULL,
    result TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (from_id, to_id)
  );

  CREATE TABLE backups (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    profile TEXT NOT NULL,
    size INTEGER,
    sha256 TEXT,
    status TEXT NOT NULL,
    detail TEXT
  );
  `,
  `
  ALTER TABLE servers ADD COLUMN config_dirty INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE servers ADD COLUMN arch TEXT;
  ALTER TABLE peer_checks ADD COLUMN fail_since TEXT;
  `,
  `
  ALTER TABLE servers ADD COLUMN core_mode TEXT NOT NULL DEFAULT 'auto';
  ALTER TABLE servers ADD COLUMN xui_user TEXT;
  ALTER TABLE servers ADD COLUMN xui_pass_sealed TEXT;
  ALTER TABLE servers ADD COLUMN external_cores TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE inbounds ADD COLUMN ext_id INTEGER;
  CREATE TABLE IF NOT EXISTS xui_counters (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    up INTEGER NOT NULL DEFAULT 0,
    down INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, email)
  );
  `,
  `
  ALTER TABLE sessions ADD COLUMN console INTEGER NOT NULL DEFAULT 0;
  `,
  `
  ALTER TABLE servers ADD COLUMN mgmt_mode TEXT NOT NULL DEFAULT 'direct';
  ALTER TABLE servers ADD COLUMN mgmt_port INTEGER;
  ALTER TABLE servers ADD COLUMN mgmt_uuid TEXT;
  ALTER TABLE servers ADD COLUMN mgmt_key_sealed TEXT;
  ALTER TABLE servers ADD COLUMN mgmt_pub TEXT;
  ALTER TABLE servers ADD COLUMN mgmt_sid TEXT;
  ALTER TABLE servers ADD COLUMN mgmt_sni TEXT;
  ALTER TABLE servers ADD COLUMN mgmt_local_port INTEGER;
  `,
  `
  ALTER TABLE templates ADD COLUMN settings TEXT NOT NULL DEFAULT '{}';
  UPDATE templates SET protocol = 'vless', settings = '{"security":"reality","transport":"tcp","flow":"xtls-rprx-vision"}' WHERE protocol = 'vless-reality';
  `,
  `
  CREATE TABLE IF NOT EXISTS exit_health (
    template_id TEXT NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    exit_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    rtt_ms INTEGER,
    mbps REAL,
    ok INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (template_id, exit_id)
  );
  `,
  `
  ALTER TABLE servers ADD COLUMN tls_state TEXT;
  `,
  `
  ALTER TABLE admins ADD COLUMN notify_off TEXT NOT NULL DEFAULT '[]';
  `,
  `
  ALTER TABLE users ADD COLUMN template_ids TEXT;
  `,
  `
  ALTER TABLE servers ADD COLUMN mgmt_via TEXT;
  `,
  `
  ALTER TABLE users ADD COLUMN note TEXT;
  `,
  `
  ALTER TABLE exit_health ADD COLUMN exit_ip TEXT;
  ALTER TABLE exit_health ADD COLUMN exit_loc TEXT;
  `,
  `
  CREATE TABLE user_devices (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, ip)
  );
  `,
  `
  CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    builtin INTEGER NOT NULL DEFAULT 0,
    perms TEXT NOT NULL DEFAULT '[]',
    scope TEXT NOT NULL DEFAULT '{}'
  );
  INSERT INTO roles (id, name, builtin, perms) VALUES
    ('admin', 'admin', 1, '["users.edit","users.delete","users.limits","configs.edit","configs.rollout","configs.delete","servers.manage","servers.protect","cores.manage","ports.groups","backups.run","settings.edit"]'),
    ('operator', 'operator', 1, '["users.edit","configs.edit","configs.rollout"]');
  `,
  `
  CREATE TABLE exit_speed (
    template_id TEXT NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    exit_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    mbps REAL
  );
  CREATE INDEX exit_speed_t ON exit_speed (template_id, exit_id, at);
  `,
  `
  ALTER TABLE users ADD COLUMN excluded_profiles TEXT;
  `,
  `
  ALTER TABLE servers ADD COLUMN paid_until TEXT;
  ALTER TABLE servers ADD COLUMN paid_warn_days INTEGER NOT NULL DEFAULT 5;
  `,
  `
  CREATE TABLE host_metrics (
    server_id TEXT NOT NULL,
    at TEXT NOT NULL,
    cpu REAL, load1 REAL, mem_pct REAL, disk_pct REAL, rx_mbps REAL, tx_mbps REAL,
    PRIMARY KEY (server_id, at)
  );
  CREATE INDEX host_metrics_at ON host_metrics (at);
  `,
  `
  -- кто создал (admins.id): по нему считаются лимиты роли «пользователей» и «конфигураций» на администратора
  ALTER TABLE users ADD COLUMN created_by INTEGER;
  ALTER TABLE templates ADD COLUMN created_by INTEGER;
  `,
  `
  -- канал управления «через конфигурацию» (mgmt_mode = 'inbound'): SSH внутри VLESS-inbound'а этой конфигурации на узле
  ALTER TABLE servers ADD COLUMN mgmt_template TEXT;
  `,
  `
  -- канал управления «через сервер» (mgmt_mode = 'jump'): SSH панели через узел-посредник mgmt_jump (servers.id)
  ALTER TABLE servers ADD COLUMN mgmt_jump TEXT;
  `,
];

export type Db = DatabaseSync;

export function openDb(dataDir: string): Db {
  const db = new DatabaseSync(path.join(dataDir, 'fleet.db'));
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec('CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)');
  const row = db.prepare('SELECT v FROM schema_version').get() as { v: number } | undefined;
  let v = row?.v ?? 0;
  if (!row) db.prepare('INSERT INTO schema_version (v) VALUES (0)').run();
  for (; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare('UPDATE schema_version SET v = ?').run(v + 1);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}

export function getSetting<T>(db: Db, key: string, fallback: T): T {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  return row ? (JSON.parse(row.value) as T) : fallback;
}

export function setSetting(db: Db, key: string, value: unknown): void {
  db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
  ).run(key, JSON.stringify(value));
}
