export type VulnReference = { label: string; url: string; reason?: string };
export type HighImpactMode = 'high-critical-only' | 'always' | 'never';

const COMMON: VulnReference[] = [
	{ label: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/', reason: 'Industry-priority web risk categories.' },
	{ label: 'MITRE CWE', url: 'https://cwe.mitre.org/', reason: 'Canonical weakness taxonomy and technical definitions.' }
];

const HIGH_IMPACT: VulnReference[] = [
	{ label: 'CISA Known Exploited Vulnerabilities Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', reason: 'Tracks vulnerabilities actively exploited in the wild.' },
	{ label: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/vuln', reason: 'CVE detail, severity scoring, and enrichment.' }
];

const BY_RULE: Record<string, VulnReference[]> = {
	'eval-usage': [
		{ label: 'OWASP A03: Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/', reason: 'Primary guidance for injection-class flaws.' },
		{ label: 'CWE-95 Eval Injection', url: 'https://cwe.mitre.org/data/definitions/95.html', reason: 'Specific weakness model for eval injection.' }
	],
	'dangerously-set-inner-html': [
		{ label: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', reason: 'Defensive patterns for output encoding and sanitization.' },
		{ label: 'CWE-79 XSS', url: 'https://cwe.mitre.org/data/definitions/79.html', reason: 'Weakness category for cross-site scripting.' }
	],
	'sql-concat-heuristic': [
		{ label: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html', reason: 'Prepared statements and query hardening guidance.' },
		{ label: 'CWE-89 SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html', reason: 'Formal weakness classification for SQL injection.' }
	],
	'command-injection-heuristic': [
		{ label: 'OWASP OS Command Injection Defense', url: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html', reason: 'Safe process execution and input handling patterns.' },
		{ label: 'CWE-78 OS Command Injection', url: 'https://cwe.mitre.org/data/definitions/78.html', reason: 'Weakness model for command injection.' }
	],
	'pem-private-key': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Operational guidance for secret lifecycle control.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Weakness category for embedded credentials.' }
	],
	'hardcoded-secret-assignment': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Operational guidance for secret lifecycle control.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Weakness category for embedded credentials.' }
	],
	'supabase-service-role-leak': [
		{ label: 'OWASP API Security Top 10', url: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/', reason: 'API-specific authz and exposure controls.' },
		{ label: 'OWASP A01: Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', reason: 'Access control failure patterns and mitigations.' }
	],
	'firebase-admin-client-path': [
		{ label: 'OWASP A01: Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', reason: 'Privileged capability misuse belongs to access control failures.' },
		{ label: 'OWASP API Security Top 10', url: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/', reason: 'API privilege boundaries and threat patterns.' }
	],
	'firebase-permissive-rules': [
		{ label: 'Firebase Security Rules Conditions', url: 'https://firebase.google.com/docs/rules/basics#security_rules_conditions', reason: 'Official guidance for restricting unauthenticated access.' },
		{ label: 'OWASP A01: Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', reason: 'Public read/write access is an access control failure.' }
	],
	'postgres-url-client-exposure': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Database credentials must stay out of client code.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Client-exposed connection strings are credential exposure risks.' }
	],
	'mysql-url-client-exposure': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Database credentials must stay out of client code.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Client-exposed connection strings are credential exposure risks.' }
	],
	'mongodb-url-client-exposure': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Database credentials must stay out of client code.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Client-exposed connection strings are credential exposure risks.' }
	],
	'sqlserver-connstring-client-exposure': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Database credentials must stay out of client code.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Client-exposed connection strings are credential exposure risks.' }
	],
	'redis-url-client-exposure': [
		{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Database credentials must stay out of client code.' },
		{ label: 'CWE-798 Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html', reason: 'Client-exposed connection strings are credential exposure risks.' }
	],
	'embedded-jwt-like': [
		{ label: 'OWASP JWT Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html', reason: 'Token handling pitfalls and secure JWT usage.' },
		{ label: 'CWE-522 Insufficiently Protected Credentials', url: 'https://cwe.mitre.org/data/definitions/522.html', reason: 'Credential exposure weakness category.' }
	],
	'lint-suppression-smell': [
		{ label: 'OWASP ASVS', url: 'https://owasp.org/www-project-application-security-verification-standard/', reason: 'Verification baseline for secure development controls.' }
	],
	'dep-vuln': [
		{ label: 'OSV.dev', url: 'https://osv.dev/', reason: 'Open source vulnerability database used to identify this advisory.' },
		{ label: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/vuln', reason: 'CVE detail, CVSS severity scoring, and enrichment.' },
		{ label: 'OWASP A06: Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/', reason: 'Primary OWASP guidance for dependency management and patching.' }
	]
};

const BY_CATEGORY: Record<string, VulnReference[]> = {
	injection: [{ label: 'OWASP A03: Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/', reason: 'Category-level injection guidance.' }],
	xss: [{ label: 'OWASP XSS Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', reason: 'Category-level output encoding/sanitization guidance.' }],
	authz: [{ label: 'OWASP A01: Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', reason: 'Category-level access-control guidance.' }],
	secrets: [{ label: 'OWASP Secrets Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', reason: 'Category-level secret handling guidance.' }],
	hygiene: [{ label: 'OWASP ASVS', url: 'https://owasp.org/www-project-application-security-verification-standard/', reason: 'Category-level secure engineering assurance guidance.' }],
	dependencies: [{ label: 'OWASP A06: Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/', reason: 'Category-level dependency patching guidance.' }]
};

export function referencesFor(
	ruleId: string,
	category: string,
	severity?: string,
	options?: { highImpactMode?: HighImpactMode }
): VulnReference[] {
	const unique = new Map<string, VulnReference>();
	const mode = options?.highImpactMode ?? 'high-critical-only';
	const sev = (severity ?? '').toLowerCase();
	const includeHighImpact = mode === 'always' || (mode === 'high-critical-only' && (sev === 'high' || sev === 'critical'));
	for (const r of [
		...(BY_RULE[ruleId] ?? []),
		...(BY_CATEGORY[category] ?? []),
		...(includeHighImpact ? HIGH_IMPACT : []),
		...COMMON
	]) {
		if (!unique.has(r.url)) unique.set(r.url, r);
	}
	return [...unique.values()];
}

export function referencesToMarkdown(refs: VulnReference[]): string {
	return refs.map((r) => `- [${r.label}](${r.url})${r.reason ? ` - ${r.reason}` : ''}`).join('\n');
}
