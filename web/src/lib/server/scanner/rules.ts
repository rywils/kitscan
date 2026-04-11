import type { EvidenceItem, RuleHit } from '../types';
import { looksLikeClientPath } from './constants';

export type ScanPhase = 'A' | 'B' | 'D';
type LineContext = { relPath: string; content: string; lines: string[]; phase: ScanPhase };

function lineExcerpt(lines: string[], lineIndex0: number, width = 200): string {
	const line = lines[lineIndex0] ?? '';
	return line.length > width ? `${line.slice(0, width)}…` : line;
}

function hit(
	ctx: LineContext,
	rule: Omit<RuleHit, 'filePath' | 'line' | 'excerpt' | 'evidence'> & { evidence?: EvidenceItem[] },
	lineIndex0: number,
	excerpt?: string
): RuleHit {
	return {
		...rule,
		filePath: ctx.relPath,
		line: lineIndex0 + 1,
		excerpt: excerpt ?? lineExcerpt(ctx.lines, lineIndex0),
		evidence: rule.evidence ?? [{ type: 'pattern', detail: `Matched ${rule.ruleId}` }]
	};
}

function classifyEvalRisk(line: string) {
	const dynamicUntrusted =
		/(req\.|request\.|params\.|query\.|body\.|input\b|location\.|window\.name|document\.cookie|postMessage)/i.test(
			line
		);
	const dynamicUnknown = /\$\{|\+\s*[a-zA-Z_$][\w$.]*/.test(line);
	const literalOnly = /eval\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(line);
	if (dynamicUntrusted) {
		return {
			severity: 'high' as const,
			confidence: 'high' as const,
			description:
				'eval() appears to use request/user-influenced data. This is generally exploitable code injection risk.',
			evidence: [{ type: 'pattern', detail: 'eval with user-controlled symbol(s)' }]
		};
	}
	if (dynamicUnknown) {
		return {
			severity: 'medium' as const,
			confidence: 'medium' as const,
			description:
				'eval() executes dynamic code; source of data is unclear. Treat as risky unless inputs are strictly controlled.',
			evidence: [{ type: 'pattern', detail: 'eval with dynamic concatenation/interpolation' }]
		};
	}
	if (literalOnly) {
		return {
			severity: 'info' as const,
			confidence: 'medium' as const,
			description:
				'eval() is called with a literal string. Not automatically exploitable via user input, but still a risky pattern.',
			evidence: [{ type: 'pattern', detail: 'eval with static literal' }]
		};
	}
	return {
		severity: 'medium' as const,
		confidence: 'low' as const,
		description: 'eval() usage detected with unclear taint source.',
		evidence: [{ type: 'api', detail: 'eval(' }]
	};
}

export function buildMatchKey(h: RuleHit): string {
	return `${h.ruleId}|${h.filePath}|${h.line}|${h.title}`;
}

/** Phase A runs conservative core checks; Phase B runs full checks. */
export function runRulesOnFile(ctx: LineContext): RuleHit[] {
	const out: RuleHit[] = [];
	const text = ctx.content;
	const clientish = looksLikeClientPath(ctx.relPath);
	const full = ctx.phase === 'B';

	for (let i = 0; i < ctx.lines.length; i++) {
		const line = ctx.lines[i] ?? '';

		if (line.includes('BEGIN PRIVATE KEY') || line.includes('BEGIN RSA PRIVATE KEY')) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'pem-private-key',
						title: 'Private key material in source',
						severity: 'critical',
						category: 'secrets',
						description: 'PEM private key appears in source.',
						remediation: 'Rotate key, remove from history, and move to secret manager/env.',
						confidence: 'high',
						evidence: [{ type: 'content', detail: 'PEM header detected' }]
					},
					i
				)
			);
		}

		if (
			/(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"\s]{12,}['"]/i.test(line) &&
			!line.includes('process.env') &&
			!line.includes('import.meta.env') &&
			!line.includes('example') &&
			!ctx.relPath.endsWith('.example')
		) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'hardcoded-secret-assignment',
						title: 'Possible hardcoded secret in assignment',
						severity: 'high',
						category: 'secrets',
						description: 'Potential hardcoded API key/token/password.',
						remediation: 'Move secrets to environment variables or secret manager.',
						confidence: 'medium',
						evidence: [{ type: 'pattern', detail: 'secret-like assignment' }]
					},
					i
				)
			);
		}

		if (clientish && /service_role/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'supabase-service-role-leak',
						title: 'Supabase service role may be exposed in client-side code',
						severity: 'critical',
						category: 'authz',
						description: 'service_role in client path can bypass RLS if exposed.',
						remediation: 'Use anon key on client, service role server-side only.',
						confidence: 'high',
						evidence: [{ type: 'keyword', detail: 'service_role in client path' }]
					},
					i
				)
			);
		}

		if (clientish && /firebase-admin|initializeApp\s*\(.*credential/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'firebase-admin-client-path',
						title: 'Firebase Admin SDK usage in client-leaning path',
						severity: 'high',
						category: 'authz',
						description: 'Admin SDK should never ship to client bundles.',
						remediation: 'Move to server route/function.',
						confidence: 'medium',
						evidence: [{ type: 'import', detail: 'firebase-admin pattern' }]
					},
					i
				)
			);
		}

		if (
			(ctx.relPath.endsWith('firestore.rules') || ctx.relPath.endsWith('storage.rules')) &&
			/allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true\b/i.test(line)
		) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'firebase-permissive-rules',
						title: 'Firebase rules allow public read/write',
						severity: 'critical',
						category: 'authz',
						description:
							'Firebase security rules appear to allow unauthenticated public access.',
						remediation:
							'Require authenticated conditions and least-privilege checks in rules.',
						confidence: 'high',
						evidence: [{ type: 'pattern', detail: 'allow read/write if true' }]
					},
					i
				)
			);
		}

		if (clientish && /postgres(?:ql)?:\/\/[^'"`\s]+/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'postgres-url-client-exposure',
						title: 'PostgreSQL connection URL in client-leaning path',
						severity: 'high',
						category: 'secrets',
						description:
							'Database connection strings should not be present in client-side code.',
						remediation: 'Move DB credentials to server-only environment configuration.',
						confidence: 'high',
						evidence: [{ type: 'pattern', detail: 'postgres://... in client path' }]
					},
					i
				)
			);
		}

		if (clientish && /mysql:\/\/[^'"`\s]+/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'mysql-url-client-exposure',
						title: 'MySQL connection URL in client-leaning path',
						severity: 'high',
						category: 'secrets',
						description:
							'Database connection strings should not be present in client-side code.',
						remediation: 'Move DB credentials to server-only environment configuration.',
						confidence: 'high',
						evidence: [{ type: 'pattern', detail: 'mysql://... in client path' }]
					},
					i
				)
			);
		}

		if (clientish && /mongodb(?:\+srv)?:\/\/[^'"`\s]+/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'mongodb-url-client-exposure',
						title: 'MongoDB connection URL in client-leaning path',
						severity: 'high',
						category: 'secrets',
						description:
							'Database connection strings should not be present in client-side code.',
						remediation: 'Move DB credentials to server-only environment configuration.',
						confidence: 'high',
						evidence: [{ type: 'pattern', detail: 'mongodb://... in client path' }]
					},
					i
				)
			);
		}

		if (
			clientish &&
			/Server=.*;Database=.*;(?:User Id|UID)=.*;(?:Password|PWD)=.*;?/i.test(line)
		) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'sqlserver-connstring-client-exposure',
						title: 'SQL Server connection string in client-leaning path',
						severity: 'high',
						category: 'secrets',
						description:
							'Database connection strings should not be present in client-side code.',
						remediation: 'Move DB credentials to server-only environment configuration.',
						confidence: 'medium',
						evidence: [{ type: 'pattern', detail: 'SQL Server connection string in client path' }]
					},
					i
				)
			);
		}

		if (clientish && /redis:\/\/[^'"`\s]*:[^'"`\s]*@[^'"`\s]+/i.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'redis-url-client-exposure',
						title: 'Redis authenticated URL in client-leaning path',
						severity: 'high',
						category: 'secrets',
						description:
							'Redis authenticated connection URLs should not be present in client-side code.',
						remediation: 'Move Redis credentials to server-only environment configuration.',
						confidence: 'high',
						evidence: [{ type: 'pattern', detail: 'redis://user:pass@host in client path' }]
					},
					i
				)
			);
		}

		if (/dangerouslySetInnerHTML/.test(line)) {
			out.push(
				hit(
					ctx,
					{
						ruleId: 'dangerously-set-inner-html',
						title: 'dangerouslySetInnerHTML (potential XSS)',
						severity: 'medium',
						category: 'xss',
						description: 'Raw HTML rendering can allow XSS with untrusted input.',
						remediation: 'Sanitize content or avoid raw HTML.',
						confidence: 'medium',
						evidence: [{ type: 'api', detail: 'dangerouslySetInnerHTML' }]
					},
					i
				)
			);
		}

		if (/\beval\s*\(/.test(line) && !line.trim().startsWith('//')) {
			const er = classifyEvalRisk(line);
			out.push(
				hit(
					ctx,
					{
						ruleId: 'eval-usage',
						title: 'eval() usage',
						severity: er.severity,
						category: 'injection',
						description: er.description,
						remediation: 'Replace eval with parser/lookup alternatives.',
						confidence: er.confidence,
						evidence: er.evidence
					},
					i
				)
			);
		}

		if (!full) continue;

		if (/(?:query|execute|raw)\s*\(\s*[`'"]/.test(line) && /(\$\{|\+\s*req\.|\+\s*params|concat)/i.test(line)) {
			out.push(hit(ctx, {
				ruleId: 'sql-concat-heuristic',
				title: 'Possible SQL built with concatenation or interpolation',
				severity: 'high',
				category: 'injection',
				description: 'Dynamic SQL construction may allow SQL injection.',
				remediation: 'Use parameterized queries/prepared statements.',
				confidence: 'low',
				evidence: [{ type: 'pattern', detail: 'query + dynamic segments' }]
			}, i));
		}

		if (/(?:exec|execSync|spawn)\s*\(/.test(line) && /(\$\{|`\$\{|\+\s*req\.|\+\s*input)/i.test(line)) {
			out.push(hit(ctx, {
				ruleId: 'command-injection-heuristic',
				title: 'Possible command execution with dynamic input',
				severity: 'high',
				category: 'injection',
				description: 'Dynamic shell command construction may allow command injection.',
				remediation: 'Use execFile/spawn argv arrays and allowlists.',
				confidence: 'low',
				evidence: [{ type: 'pattern', detail: 'exec/spawn + dynamic input' }]
			}, i));
		}

		if (/@ts-ignore|eslint-disable-next-line\s+no-eval|eslint-disable.*security/i.test(line)) {
			out.push(hit(ctx, {
				ruleId: 'lint-suppression-smell',
				title: 'Security-related lint or type suppression',
				severity: 'info',
				category: 'hygiene',
				description: 'Suppression may hide issues.',
				remediation: 'Review and minimize suppression scope.',
				confidence: 'low',
				evidence: [{ type: 'comment', detail: 'suppression directive' }]
			}, i));
		}
	}

	if (full) {
		const jwtLike = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
		if (jwtLike.test(text) && !ctx.relPath.includes('.lock')) {
			const m = text.match(jwtLike);
			const idx = m && m.index != null ? text.slice(0, m.index).split('\n').length - 1 : 0;
			out.push(
				hit(
					ctx,
					{
						ruleId: 'embedded-jwt-like',
						title: 'Embedded JWT-like string',
						severity: 'medium',
						category: 'secrets',
						description: 'JWT-like strings may be live credentials.',
						remediation: 'Rotate/remove real tokens; keep only safe test samples.',
						confidence: 'low',
						evidence: [{ type: 'pattern', detail: 'JWT-shaped string' }]
					},
					Math.max(0, idx),
					m ? (m[0].length > 120 ? `${m[0].slice(0, 120)}…` : m[0]) : undefined
				)
			);
		}
	}

	return dedupeHits(out);
}

function dedupeHits(hits: RuleHit[]): RuleHit[] {
	const seen = new Set<string>();
	const out: RuleHit[] = [];
	for (const h of hits) {
		const key = `${h.ruleId}:${h.filePath}:${h.line}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(h);
	}
	return out;
}
