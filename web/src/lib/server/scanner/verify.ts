import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FindingRow } from '../db/schema';
import type { VerificationStatus } from '../types';
import { buildFixPrompt } from './prompt';
import type { RuleHit } from '../types';

function snippetAround(lines: string[], line1: number, pad = 3): string {
	const i0 = Math.max(0, line1 - 1 - pad);
	const i1 = Math.min(lines.length, line1 + pad);
	const parts: string[] = [];
	for (let i = i0; i < i1; i++) {
		parts.push(`${i + 1}: ${lines[i] ?? ''}`);
	}
	return parts.join('\n');
}

function rowToHit(f: FindingRow): RuleHit {
	return {
		ruleId: f.ruleId,
		title: f.title,
		severity: f.severity as RuleHit['severity'],
		category: f.category,
		description: f.description,
		remediation: f.remediation,
		confidence: f.confidence as RuleHit['confidence'],
		filePath: f.filePath,
		line: f.line ?? 1,
		excerpt: f.excerpt ?? '',
		evidence: JSON.parse(f.evidenceJson || '[]') as RuleHit['evidence']
	};
}

export function verifyFinding(
	sourceRootAbs: string,
	finding: FindingRow
): {
	status: VerificationStatus;
	verifiedSnippet: string | null;
	fixPrompt: string;
} {
	const abs = join(sourceRootAbs, finding.filePath);
	let raw: string;
	try {
		raw = readFileSync(abs, 'utf8');
	} catch {
		const hit = rowToHit(finding);
		return {
			status: 'inconclusive',
			verifiedSnippet: null,
			fixPrompt: buildFixPrompt(hit, finding.excerpt ?? null)
		};
	}

	const lines = raw.split(/\r?\n/);
	const line1 = finding.line ?? 1;
	const target = lines[line1 - 1] ?? '';
	const excerpt = (finding.excerpt ?? '').trim();
	const snip = snippetAround(lines, line1);

	let status: VerificationStatus;
	if (line1 < 1 || line1 > lines.length) {
		status = 'false_positive';
	} else if (excerpt.length >= 8 && target.includes(excerpt.slice(0, Math.min(40, excerpt.length)))) {
		status = 'confirmed';
	} else if (excerpt.length > 0 && raw.includes(excerpt.slice(0, Math.min(80, excerpt.length)))) {
		status = 'likely';
	} else if (finding.ruleId === 'embedded-jwt-like' && /eyJ[A-Za-z0-9_-]{10,}\./.test(target)) {
		status = 'likely';
	} else if (target.trim().length > 0) {
		status = 'likely';
	} else {
		status = 'false_positive';
	}

	const hit = rowToHit(finding);
	const fixPrompt = buildFixPrompt(hit, snip);

	return { status, verifiedSnippet: snip, fixPrompt };
}
