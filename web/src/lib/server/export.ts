import type { FindingRow, ScanRow } from './db/schema';
import { referencesFor } from '$lib/references';

export function exportJson(scan: ScanRow, findingRows: FindingRow[]) {
	return JSON.stringify(
		{
			scan: {
				id: scan.id,
				createdAt: scan.createdAt,
				sourcePath: scan.sourcePath,
				status: scan.status,
				steps: JSON.parse(scan.stepsJson || '[]'),
				errorMessage: scan.errorMessage,
				finishedAt: scan.finishedAt,
				assessmentFinishedAt: scan.assessmentFinishedAt,
				sourceScanFinishedAt: scan.sourceScanFinishedAt
			},
			findings: findingRows.map((f) => ({
				id: f.id,
				ruleId: f.ruleId,
				title: f.title,
				severity: f.severity,
				category: f.category,
				description: f.description,
				remediation: f.remediation,
				confidence: f.confidence,
				filePath: f.filePath,
				line: f.line,
				excerpt: f.excerpt,
				evidence: JSON.parse(f.evidenceJson || '[]'),
				verificationStatus: f.verificationStatus,
				verifiedSnippet: f.verifiedSnippet,
				verifiedAt: f.verifiedAt,
				fixPrompt: f.fixPrompt,
				references: referencesFor(f.ruleId, f.category, f.severity)
			}))
		},
		null,
		2
	);
}

export function exportMarkdown(scan: ScanRow, findingRows: FindingRow[]): string {
	const steps = JSON.parse(scan.stepsJson || '[]') as { level: string; message: string; t: number }[];
	const lines: string[] = [];
	lines.push(`# Security scan report`);
	lines.push('');
	lines.push(`- **Scan ID:** \`${scan.id}\``);
	lines.push(`- **Source:** \`${scan.sourcePath}\``);
	lines.push(`- **Status:** ${scan.status}`);
	lines.push(`- **Created:** ${new Date(scan.createdAt).toISOString()}`);
	if (scan.finishedAt) lines.push(`- **Finished:** ${new Date(scan.finishedAt).toISOString()}`);
	lines.push(`- **Phase A complete:** ${scan.assessmentFinishedAt ? 'yes' : 'no'}`);
	lines.push(`- **Phase B complete:** ${scan.sourceScanFinishedAt ? 'yes' : 'no'}`);
	lines.push('');
	lines.push('## Steps');
	lines.push('');
	for (const s of steps) {
		lines.push(`- **${s.level}** — ${s.message}`);
	}
	lines.push('');
	lines.push(`## Findings (${findingRows.length})`);
	lines.push('');
	for (const f of findingRows) {
		lines.push(`### ${f.title}`);
		lines.push('');
		lines.push(`- **Severity:** ${f.severity}`);
		lines.push(`- **Category:** ${f.category}`);
		lines.push(`- **Confidence:** ${f.confidence}`);
		lines.push(`- **Location:** \`${f.filePath}\`${f.line != null ? ` (line ${f.line})` : ''}`);
		if (f.verificationStatus) lines.push(`- **Verification:** ${f.verificationStatus}`);
		lines.push('');
		lines.push('**Description:**');
		lines.push(f.description);
		lines.push('');
		lines.push('**Remediation:**');
		lines.push(f.remediation);
		lines.push('');
		if (f.excerpt) {
			lines.push('**Excerpt:**');
			lines.push('```');
			lines.push(f.excerpt);
			lines.push('```');
			lines.push('');
		}
		const refs = referencesFor(f.ruleId, f.category, f.severity);
		if (refs.length > 0) {
			lines.push('**References:**');
			for (const r of refs) lines.push(`- [${r.label}](${r.url})`);
			lines.push('');
		}

		if (f.verifiedSnippet) {
			lines.push('**Verified context:**');
			lines.push('```');
			lines.push(f.verifiedSnippet);
			lines.push('```');
			lines.push('');
		}
		lines.push('---');
		lines.push('');
	}
	return lines.join('\n');
}
