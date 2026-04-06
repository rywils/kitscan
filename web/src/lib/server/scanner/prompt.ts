import type { RuleHit } from '../types';

export function buildFixPrompt(hit: RuleHit, snippet: string | null): string {
	const ctx = snippet?.trim() || hit.excerpt.trim();
	return [
		'You are helping fix a security issue in my codebase.',
		'',
		`**Issue:** ${hit.title}`,
		`**Severity:** ${hit.severity}`,
		`**File:** ${hit.filePath} (line ${hit.line})`,
		`**Category:** ${hit.category}`,
		'',
		'**Why this matters:**',
		hit.description,
		'',
		'**Remediation guidance:**',
		hit.remediation,
		'',
		'**Code context:**',
		'```',
		ctx,
		'```',
		'',
		'Apply the smallest safe change. Prefer server-side enforcement, secrets in env (never client), parameterized queries, and policy/RLS where relevant. Add a short comment if behavior is non-obvious.'
	].join('\n');
}
