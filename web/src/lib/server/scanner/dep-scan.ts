import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { RuleHit } from '../types';

type DepEntry = { name: string; version: string; source: string };

function parsePackageLockV2(content: string, relPath: string): DepEntry[] {
	let obj: unknown;
	try {
		obj = JSON.parse(content);
	} catch {
		return [];
	}
	if (typeof obj !== 'object' || obj === null) return [];
	const packages = (obj as Record<string, unknown>).packages;
	if (typeof packages !== 'object' || packages === null) return [];
	const out: DepEntry[] = [];
	for (const [key, val] of Object.entries(packages as Record<string, unknown>)) {
		if (!key || !key.startsWith('node_modules/')) continue;
		if (typeof val !== 'object' || val === null) continue;
		const v = val as Record<string, unknown>;
		if (v.dev === true || v.devOptional === true) continue;
		const version = typeof v.version === 'string' ? v.version : null;
		if (!version) continue;
		const name = key.replace(/^node_modules\//, '').replace(/\/node_modules\//g, '/');
		out.push({ name, version, source: relPath });
	}
	return out;
}

function parsePnpmLock(content: string, relPath: string): DepEntry[] {
	const out: DepEntry[] = [];
	const lines = content.split(/\r?\n/);

	let inPackages = false;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i] ?? '';

		if (/^[a-zA-Z]/.test(line) && line.endsWith(':')) {
			inPackages = line.startsWith('packages:') || line.startsWith('snapshots:');
			continue;
		}

		if (!inPackages) continue;

		const pkgHeader = line.match(/^  ['"]?([^'":\s]+)['"]?:\s*$/);
		if (!pkgHeader) continue;

		const raw = pkgHeader[1]!;
		let name: string | null = null;
		let version: string | null = null;
		const stripped = raw.startsWith('/') ? raw.slice(1) : raw;

		const atMatch = stripped.match(/^(@?[^@]+)@([^\s(]+)/);
		if (atMatch) {
			name = atMatch[1]!;
			version = atMatch[2]!.replace(/\(.*$/, '');
		} else {
			const parts = stripped.split('/');
			if (parts.length >= 2) {
				const maybeVersion = parts[parts.length - 1]!;
				if (/^\d/.test(maybeVersion)) {
					version = maybeVersion;
					name = parts.slice(0, -1).join('/');
				}
			}
		}

		if (!name || !version) continue;

		let isDev = false;
		for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
			const next = lines[j] ?? '';
			if (/^  [a-zA-Z]/.test(next) && next.endsWith(':')) break;
			if (/^\s{4,}dev:\s*true/.test(next)) {
				isDev = true;
				break;
			}
		}
		if (isDev) continue;

		out.push({ name, version, source: relPath });
	}
	return out;
}

function parseYarnLock(content: string, relPath: string): DepEntry[] {
	const out: DepEntry[] = [];
	const lines = content.split(/\r?\n/);

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i] ?? '';
		if (!line.endsWith(':') || line.startsWith(' ') || line.startsWith('#')) continue;

		const header = line.replace(/:$/, '').replace(/^"/, '').replace(/"$/, '').split(',')[0]!.trim().replace(/^"/, '');
		const atIdx = header.lastIndexOf('@');
		if (atIdx <= 0) continue;
		const name = header.slice(0, atIdx);

		let version: string | null = null;
		for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
			const next = lines[j] ?? '';
			if (!next.startsWith(' ')) break;
			const vm = next.match(/^\s+version\s+"([^"]+)"/);
			if (vm) {
				version = vm[1]!;
				break;
			}
		}
		if (!version) continue;
		out.push({ name, version, source: relPath });
	}
	return out;
}

function parseCargoLock(content: string, relPath: string): DepEntry[] {
	const out: DepEntry[] = [];
	const blocks = content.split(/\[\[package\]\]/);
	for (const block of blocks.slice(1)) {
		const nameM = block.match(/name\s*=\s*"([^"]+)"/);
		const verM = block.match(/version\s*=\s*"([^"]+)"/);
		if (!nameM || !verM) continue;
		out.push({ name: nameM[1]!, version: verM[1]!, source: relPath });
	}
	return out;
}

const LOCKFILE_NAMES = new Set([
	'package-lock.json',
	'pnpm-lock.yaml',
	'yarn.lock',
	'Cargo.lock'
]);

const SKIP_DIRS = new Set([
	'node_modules', '.git', 'dist', 'build', '.svelte-kit',
	'.next', 'coverage', '.nuxt', '.output', 'target', 'vendor',
	'__pycache__', '.venv', 'venv'
]);

function findLockfiles(rootAbs: string): { absPath: string; relPath: string; name: string }[] {
	const found: { absPath: string; relPath: string; name: string }[] = [];
	const stack = [rootAbs];
	while (stack.length > 0) {
		const dir = stack.pop()!;
		let names: string[];
		try { names = readdirSync(dir); } catch { continue; }
		for (const name of names) {
			const abs = join(dir, name);
			let st;
			try { st = statSync(abs); } catch { continue; }
			if (st.isDirectory()) {
				if (!SKIP_DIRS.has(name)) stack.push(abs);
			} else if (st.isFile() && LOCKFILE_NAMES.has(name)) {
				const relPath = relative(rootAbs, abs).split(sep).join('/');
				found.push({ absPath: abs, relPath, name });
			}
		}
	}
	return found;
}

type OsvPackage = { name: string; version: string; ecosystem: string };
type OsvQuery = { package: OsvPackage };
type OsvBatchRequest = { queries: OsvQuery[] };

type OsvSeverity = { type: string; score: string };
type OsvVuln = {
	id: string;
	summary?: string;
	details?: string;
	aliases?: string[];
	severity?: OsvSeverity[];
	affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { type: string; events?: { introduced?: string; fixed?: string }[] }[] }[];
	database_specific?: { severity?: string };
};
type OsvBatchResult = { results: { vulns?: OsvVuln[] }[] };

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const OSV_BATCH_SIZE = 1000;
const OSV_TIMEOUT_MS = 30_000;
const OSV_DETAIL_CONCURRENCY = 20;

function ecosystemForLockfile(lockfileName: string): string {
	if (lockfileName === 'Cargo.lock') return 'crates.io';
	return 'npm';
}

async function queryOsv(queries: OsvQuery[]): Promise<OsvBatchResult> {
	const body: OsvBatchRequest = { queries };
	const ctrl = new AbortController();
	const timer = setTimeout(() => ctrl.abort(), OSV_TIMEOUT_MS);
	try {
		const res = await fetch(OSV_BATCH_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			signal: ctrl.signal
		});
		if (!res.ok) throw new Error(`OSV API returned ${res.status}`);
		return (await res.json()) as OsvBatchResult;
	} finally {
		clearTimeout(timer);
	}
}

async function fetchOsvVulnDetail(id: string): Promise<OsvVuln | null> {
	const ctrl = new AbortController();
	const timer = setTimeout(() => ctrl.abort(), OSV_TIMEOUT_MS);
	try {
		const res = await fetch(`${OSV_VULN_URL}/${id}`, { signal: ctrl.signal });
		if (!res.ok) return null;
		return (await res.json()) as OsvVuln;
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

async function fetchOsvVulnDetails(ids: string[]): Promise<Map<string, OsvVuln>> {
	const map = new Map<string, OsvVuln>();
	for (let i = 0; i < ids.length; i += OSV_DETAIL_CONCURRENCY) {
		const batch = ids.slice(i, i + OSV_DETAIL_CONCURRENCY);
		const results = await Promise.all(batch.map((id) => fetchOsvVulnDetail(id)));
		for (let j = 0; j < batch.length; j++) {
			const detail = results[j];
			if (detail) map.set(batch[j]!, detail);
		}
	}
	return map;
}

function osvSeverityToInternal(vuln: OsvVuln): RuleHit['severity'] {
	const ds = vuln.database_specific?.severity?.toUpperCase();
	if (ds === 'CRITICAL') return 'critical';
	if (ds === 'HIGH') return 'high';
	if (ds === 'MODERATE' || ds === 'MEDIUM') return 'medium';
	if (ds === 'LOW') return 'low';

	for (const s of vuln.severity ?? []) {
		if (s.type === 'CVSS_V3' || s.type === 'CVSS_V2') {
			const score = parseFloat(s.score);
			if (!isNaN(score)) {
				if (score >= 9.0) return 'critical';
				if (score >= 7.0) return 'high';
				if (score >= 4.0) return 'medium';
				return 'low';
			}
		}
	}

	return 'medium';
}

function fixedVersion(vuln: OsvVuln, ecosystem: string): string | null {
	for (const aff of vuln.affected ?? []) {
		if (aff.package?.ecosystem?.toLowerCase() !== ecosystem.toLowerCase()) continue;
		for (const range of aff.ranges ?? []) {
			for (const evt of range.events ?? []) {
				if (evt.fixed) return evt.fixed;
			}
		}
	}
	return null;
}

function parseSemver(v: string): [number, number, number] {
	const clean = v.replace(/^[^0-9]*/, '').split(/[-+]/)[0] ?? '';
	const parts = clean.split('.').map((p) => parseInt(p, 10) || 0);
	return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function semverLt(a: string, b: string): boolean {
	const [aMaj, aMin, aPat] = parseSemver(a);
	const [bMaj, bMin, bPat] = parseSemver(b);
	if (aMaj !== bMaj) return aMaj < bMaj;
	if (aMin !== bMin) return aMin < bMin;
	return aPat < bPat;
}

function semverGte(a: string, b: string): boolean {
	return !semverLt(a, b);
}

function versionIsVulnerable(vuln: OsvVuln, packageVersion: string, ecosystem: string): boolean {
	const affectedForEco = (vuln.affected ?? []).filter(
		(aff) => aff.package?.ecosystem?.toLowerCase() === ecosystem.toLowerCase()
	);
	if (affectedForEco.length === 0) return false;

	for (const aff of affectedForEco) {
		for (const range of aff.ranges ?? []) {
			let introduced: string | null = null;
			let fixed: string | null = null;
			for (const evt of range.events ?? []) {
				if (evt.introduced != null) introduced = evt.introduced;
				if (evt.fixed != null) fixed = evt.fixed;
			}
			if (introduced == null) continue;
			const afterIntroduced = introduced === '0' || semverGte(packageVersion, introduced);
			const beforeFixed = fixed == null || semverLt(packageVersion, fixed);
			if (afterIntroduced && beforeFixed) return true;
		}
	}
	return false;
}

export type DepScanResult = {
	hits: RuleHit[];
	lockfilesFound: string[];
	packagesQueried: number;
	error?: string;
};

export async function runDepScan(rootAbs: string): Promise<DepScanResult> {
	const lockfiles = findLockfiles(rootAbs);
	if (lockfiles.length === 0) {
		return { hits: [], lockfilesFound: [], packagesQueried: 0 };
	}

	const allEntries: (DepEntry & { ecosystem: string })[] = [];
	for (const lf of lockfiles) {
		let content: string;
		try { content = readFileSync(lf.absPath, 'utf8'); } catch { continue; }
		const eco = ecosystemForLockfile(lf.name);
		let parsed: DepEntry[] = [];
		if (lf.name === 'package-lock.json') parsed = parsePackageLockV2(content, lf.relPath);
		else if (lf.name === 'pnpm-lock.yaml') parsed = parsePnpmLock(content, lf.relPath);
		else if (lf.name === 'yarn.lock') parsed = parseYarnLock(content, lf.relPath);
		else if (lf.name === 'Cargo.lock') parsed = parseCargoLock(content, lf.relPath);
		for (const e of parsed) allEntries.push({ ...e, ecosystem: eco });
	}

	if (allEntries.length === 0) {
		return { hits: [], lockfilesFound: lockfiles.map((l) => l.relPath), packagesQueried: 0 };
	}

	const seen = new Map<string, DepEntry & { ecosystem: string }>();
	for (const e of allEntries) {
		const key = `${e.ecosystem}:${e.name}@${e.version}`;
		if (!seen.has(key)) seen.set(key, e);
	}
	const unique = [...seen.values()];

	const queries: OsvQuery[] = unique.map((e) => ({
		package: { name: e.name, version: e.version, ecosystem: e.ecosystem }
	}));

	let osvResult: OsvBatchResult;
	try {
		const batches: OsvBatchResult['results'] = [];
		for (let i = 0; i < queries.length; i += OSV_BATCH_SIZE) {
			const slice = queries.slice(i, i + OSV_BATCH_SIZE);
			const r = await queryOsv(slice);
			batches.push(...r.results);
		}
		osvResult = { results: batches };
	} catch (err) {
		return {
			hits: [],
			lockfilesFound: lockfiles.map((l) => l.relPath),
			packagesQueried: unique.length,
			error: err instanceof Error ? err.message : String(err)
		};
	}

	const vulnIdToEntries = new Map<string, (DepEntry & { ecosystem: string })[]>();
	for (let qi = 0; qi < unique.length; qi++) {
		const entry = unique[qi]!;
		const result = osvResult.results[qi];
		for (const v of result?.vulns ?? []) {
			if (!vulnIdToEntries.has(v.id)) vulnIdToEntries.set(v.id, []);
			vulnIdToEntries.get(v.id)!.push(entry);
		}
	}

	if (vulnIdToEntries.size === 0) {
		return { hits: [], lockfilesFound: lockfiles.map((l) => l.relPath), packagesQueried: unique.length };
	}

	let detailMap: Map<string, OsvVuln>;
	try {
		detailMap = await fetchOsvVulnDetails([...vulnIdToEntries.keys()]);
	} catch (err) {
		return {
			hits: [],
			lockfilesFound: lockfiles.map((l) => l.relPath),
			packagesQueried: unique.length,
			error: err instanceof Error ? err.message : String(err)
		};
	}

	const hits: RuleHit[] = [];
	for (const [vulnId, entries] of vulnIdToEntries) {
		const vuln = detailMap.get(vulnId);
		if (!vuln) continue;

		const ecosystem = entries[0]?.ecosystem ?? 'npm';
		const vulnerableEntries = entries.filter((e) => versionIsVulnerable(vuln, e.version, ecosystem));
		if (vulnerableEntries.length === 0) continue;

		const primaryId = vuln.id;
		const aliases = vuln.aliases ?? [];
		const cveId = [primaryId, ...aliases].find((id) => id.startsWith('CVE-')) ?? primaryId;
		const severity = osvSeverityToInternal(vuln);
		const fixed = fixedVersion(vuln, ecosystem);
		const summary = vuln.summary ?? vuln.details?.split('\n')[0] ?? 'Vulnerability detected';
		const nvdUrl = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : `https://osv.dev/vulnerability/${primaryId}`;

		for (const entry of vulnerableEntries) {
			const ruleHit: RuleHit = {
				ruleId: 'dep-vuln',
				title: `${entry.name}@${entry.version}: ${cveId}`,
				severity,
				category: 'dependencies',
				description: summary,
				remediation: fixed
					? `Upgrade ${entry.name} to ${fixed} or later.`
					: `No fix available yet. Review ${cveId} and consider alternatives.`,
				confidence: 'high',
				filePath: entry.source,
				line: 1,
				excerpt: `${entry.name}@${entry.version}`,
				evidence: [
					{ type: 'advisory', detail: primaryId },
					...(cveId !== primaryId ? [{ type: 'cve', detail: cveId }] : []),
					{ type: 'url', detail: nvdUrl }
				]
			};
			hits.push(ruleHit);
		}
	}

	return {
		hits,
		lockfilesFound: lockfiles.map((l) => l.relPath),
		packagesQueried: unique.length
	};
}
