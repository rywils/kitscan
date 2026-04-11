import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import * as schema from './schema';

const INIT_SQL = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY NOT NULL,
  created_at INTEGER NOT NULL,
  source_path TEXT NOT NULL,
  status TEXT NOT NULL,
  steps_json TEXT NOT NULL DEFAULT '[]',
  error_message TEXT,
  finished_at INTEGER,
  assessment_finished_at INTEGER,
  source_scan_finished_at INTEGER,
  dep_scan_finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS scans_created_idx ON scans (created_at);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY NOT NULL,
  scan_id TEXT NOT NULL,
  phase TEXT NOT NULL DEFAULT 'A',
  match_key TEXT NOT NULL DEFAULT '',
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  remediation TEXT NOT NULL,
  confidence TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line INTEGER,
  excerpt TEXT,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  verification_status TEXT,
  verified_snippet TEXT,
  verified_at INTEGER,
  fix_prompt TEXT NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings (scan_id);
`;

let _db: ReturnType<typeof drizzle<typeof schema>> | null = null;
let _raw: Database.Database | null = null;

export function getDbPath(): string {
	const fromEnv = process.env.SCANNER_DB_PATH;
	if (fromEnv) return fromEnv;
	return join(process.cwd(), 'data', 'scanner.db');
}

function ensureColumn(raw: Database.Database, table: string, column: string, ddl: string) {
	const cols = raw.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
	if (cols.some((c) => c.name === column)) return;
	raw.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

export function getDb() {
	if (_db) return _db;
	const path = getDbPath();
	mkdirSync(dirname(path), { recursive: true });
	_raw = new Database(path);
	_raw.pragma('journal_mode = WAL');
	_raw.pragma('foreign_keys = ON');
	_raw.exec(INIT_SQL);
	ensureColumn(_raw, 'scans', 'assessment_finished_at', 'assessment_finished_at INTEGER');
	ensureColumn(_raw, 'scans', 'source_scan_finished_at', 'source_scan_finished_at INTEGER');
	ensureColumn(_raw, 'scans', 'dep_scan_finished_at', 'dep_scan_finished_at INTEGER');
	ensureColumn(_raw, 'findings', 'phase', "phase TEXT NOT NULL DEFAULT 'A'");
	ensureColumn(_raw, 'findings', 'match_key', "match_key TEXT NOT NULL DEFAULT ''");
	_raw.exec('CREATE INDEX IF NOT EXISTS findings_scan_phase_idx ON findings (scan_id, phase)');
	_db = drizzle(_raw, { schema });
	return _db;
}

export function closeDb() {
	if (_raw) {
		_raw.close();
		_raw = null;
		_db = null;
	}
}

export { schema };
