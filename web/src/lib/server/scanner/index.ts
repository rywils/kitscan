import { basename } from 'node:path';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { and, eq } from 'drizzle-orm';
import { findings, scans } from '../db/schema';
import { getDb } from '../db';
import type { RuleHit, ScanStatus, ScanStep } from '../types';
import { buildFixPrompt } from './prompt';
import { buildMatchKey, runRulesOnFile, type ScanPhase } from './rules';
import { runDepScan } from './dep-scan';
import { collectTextFiles, readUtf8File } from './walk';

const VERBOSE_LIMIT = 2000;

function pushStep(steps: ScanStep[], level: ScanStep['level'], message: string) {
	steps.push({ t: Date.now(), level, message });
}

function persistSteps(scanId: string, steps: ScanStep[]) {
	getDb().update(scans).set({ stepsJson: JSON.stringify(steps) }).where(eq(scans.id, scanId)).run();
}

function setScanState(
	scanId: string,
	state: Partial<{
		status: ScanStatus;
		errorMessage: string | null;
		finishedAt: number | null;
		assessmentFinishedAt: number | null;
		sourceScanFinishedAt: number | null;
		depScanFinishedAt: number | null;
		stepsJson: string;
	}>
) {
	getDb().update(scans).set(state).where(eq(scans.id, scanId)).run();
}

export function resolveSourceRoot(inputPath: string): { ok: true; path: string } | { ok: false; error: string } {
	const trimmed = inputPath.trim();
	if (!trimmed) return { ok: false, error: 'Path is empty' };
	let resolved: string;
	try {
		resolved = realpathSync(trimmed);
	} catch {
		return { ok: false, error: 'Path does not exist or is not reachable' };
	}
	if (!existsSync(resolved)) return { ok: false, error: 'Path does not exist' };
	let st;
	try {
		st = statSync(resolved);
	} catch {
		return { ok: false, error: 'Cannot stat path' };
	}
	if (!st.isDirectory()) return { ok: false, error: 'Path must be a directory' };
	return { ok: true, path: resolved };
}

function prepareRun(scanId: string, steps: ScanStep[]) {
	setScanState(scanId, {
		status: 'running',
		errorMessage: null,
		finishedAt: null,
		stepsJson: JSON.stringify(steps)
	});
}

function markFailure(scanId: string, steps: ScanStep[], message: string) {
	pushStep(steps, 'error', message);
	setScanState(scanId, {
		status: 'failed',
		errorMessage: message,
		finishedAt: Date.now(),
		stepsJson: JSON.stringify(steps)
	});
}

function storeFindings(scanId: string, phase: ScanPhase, hits: ReturnType<typeof runRulesOnFile>) {
	const db = getDb();
	db.delete(findings).where(and(eq(findings.scanId, scanId), eq(findings.phase, phase))).run();
	for (const h of hits) {
		db.insert(findings)
			.values({
				id: crypto.randomUUID(),
				scanId,
				phase,
				matchKey: buildMatchKey(h),
				ruleId: h.ruleId,
				title: h.title,
				severity: h.severity,
				category: h.category,
				description: h.description,
				remediation: h.remediation,
				confidence: h.confidence,
				filePath: h.filePath,
				line: h.line,
				excerpt: h.excerpt,
				evidenceJson: JSON.stringify(h.evidence),
				verificationStatus: null,
				verifiedSnippet: null,
				verifiedAt: null,
				fixPrompt: buildFixPrompt(h, h.excerpt)
			})
			.run();
	}
}

function appendFindings(scanId: string, phase: ScanPhase, hits: RuleHit[]) {
	const db = getDb();
	for (const h of hits) {
		db.insert(findings)
			.values({
				id: crypto.randomUUID(),
				scanId,
				phase,
				matchKey: buildMatchKey(h),
				ruleId: h.ruleId,
				title: h.title,
				severity: h.severity,
				category: h.category,
				description: h.description,
				remediation: h.remediation,
				confidence: h.confidence,
				filePath: h.filePath,
				line: h.line,
				excerpt: h.excerpt,
				evidenceJson: JSON.stringify(h.evidence),
				verificationStatus: null,
				verifiedSnippet: null,
				verifiedAt: null,
				fixPrompt: buildFixPrompt(h, h.excerpt)
			})
			.run();
	}
}

function runRulePass(scanId: string, sourcePath: string, phase: ScanPhase, steps: ScanStep[], verbose: boolean) {
	const root = resolveSourceRoot(sourcePath);
	if (!root.ok) {
		throw new Error(root.error);
	}
	const { files, truncated } = collectTextFiles(root.path);
	pushStep(steps, 'info', `[Phase ${phase}] Files to inspect: ${files.length}`);
	if (truncated) pushStep(steps, 'warn', `[Phase ${phase}] File list truncated by safety limits.`);

	const hits: ReturnType<typeof runRulesOnFile> = [];
	let verboseCount = 0;
	let skippedVerbose = 0;
	for (const f of files) {
		if (verbose) {
			if (verboseCount < VERBOSE_LIMIT) {
				pushStep(steps, 'info', `[Phase ${phase}][file] ${f.relPath}`);
				verboseCount++;
			} else {
				skippedVerbose++;
			}
		}
		const content = readUtf8File(f.absPath);
		if (content == null) continue;
		const lines = content.split(/\r?\n/);
		hits.push(...runRulesOnFile({ relPath: f.relPath, content, lines, phase }));
	}
	if (verbose && skippedVerbose > 0) {
		pushStep(steps, 'warn', `[Phase ${phase}] Verbose output truncated after ${VERBOSE_LIMIT} files (${skippedVerbose} omitted).`);
	}
	storeFindings(scanId, phase, hits);
	pushStep(steps, 'info', `[Phase ${phase}] Findings stored: ${hits.length}`);
}

export async function executeAssessment(scanId: string): Promise<void> {
	const db = getDb();
	const row = db.select().from(scans).where(eq(scans.id, scanId)).get();
	if (!row) return;
	let steps: ScanStep[] = [];
	try {
		steps = JSON.parse(row.stepsJson || '[]') as ScanStep[];
	} catch {
		steps = [];
	}

	try {
		prepareRun(scanId, steps);
		pushStep(steps, 'info', '[Phase A] Assessment started');
		pushStep(steps, 'info', `Input path: ${row.sourcePath}`);
		runRulePass(scanId, row.sourcePath, 'A', steps, true);

		pushStep(steps, 'info', '[Phase A] Complete. Run Phase B for deeper analysis, or Dep Scan for dependency vulnerabilities.');
		setScanState(scanId, {
			status: 'completed',
			errorMessage: null,
			finishedAt: Date.now(),
			assessmentFinishedAt: Date.now(),
			stepsJson: JSON.stringify(steps)
		});
	} catch (e) {
		markFailure(scanId, steps, e instanceof Error ? e.message : String(e));
	}
}

export async function executeDepScan(scanId: string): Promise<void> {
	const db = getDb();
	const row = db.select().from(scans).where(eq(scans.id, scanId)).get();
	if (!row) return;
	let steps: ScanStep[] = [];
	try {
		steps = JSON.parse(row.stepsJson || '[]') as ScanStep[];
	} catch {
		steps = [];
	}

	try {
		prepareRun(scanId, steps);
		pushStep(steps, 'info', '[Phase D] Dependency vulnerability scan started');
		persistSteps(scanId, steps);
		const depResult = await runDepScan(row.sourcePath);
		if (depResult.error) {
			pushStep(steps, 'warn', `[Phase D] Dependency scan error: ${depResult.error}`);
		} else {
			pushStep(steps, 'info', `[Phase D] ${depResult.lockfilesFound.length} lockfile(s) found, ${depResult.packagesQueried} packages queried, ${depResult.hits.length} vulnerabilities found.`);
		}
		const db2 = getDb();
		db2.delete(findings).where(and(eq(findings.scanId, scanId), eq(findings.phase, 'D'))).run();
		if (depResult.hits.length > 0) {
			appendFindings(scanId, 'D', depResult.hits);
		}
		pushStep(steps, 'info', '[Phase D] Complete.');
		setScanState(scanId, {
			status: 'completed',
			errorMessage: null,
			finishedAt: Date.now(),
			depScanFinishedAt: Date.now(),
			stepsJson: JSON.stringify(steps)
		});
	} catch (e) {
		markFailure(scanId, steps, e instanceof Error ? e.message : String(e));
	}
}

export async function executeSourceScan(scanId: string): Promise<void> {
	const db = getDb();
	const row = db.select().from(scans).where(eq(scans.id, scanId)).get();
	if (!row) return;
	let steps: ScanStep[] = [];
	try {
		steps = JSON.parse(row.stepsJson || '[]') as ScanStep[];
	} catch {
		steps = [];
	}

	try {
		prepareRun(scanId, steps);
		pushStep(steps, 'info', '[Phase B] Secondary source scan started');
		runRulePass(scanId, row.sourcePath, 'B', steps, true);
		pushStep(steps, 'info', '[Phase B] Complete. Compare A vs B in diff/final boxes.');
		setScanState(scanId, {
			status: 'completed',
			errorMessage: null,
			finishedAt: Date.now(),
			sourceScanFinishedAt: Date.now(),
			stepsJson: JSON.stringify(steps)
		});
	} catch (e) {
		markFailure(scanId, steps, e instanceof Error ? e.message : String(e));
	}
}

export function summarizePath(path: string): string {
	return basename(path) || path;
}
