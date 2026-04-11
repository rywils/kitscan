import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const scans = sqliteTable(
	'scans',
	{
		id: text('id').primaryKey(),
		createdAt: integer('created_at').notNull(),
		sourcePath: text('source_path').notNull(),
		status: text('status').notNull(),
		stepsJson: text('steps_json').notNull().default('[]'),
		errorMessage: text('error_message'),
		finishedAt: integer('finished_at'),
		assessmentFinishedAt: integer('assessment_finished_at'),
		sourceScanFinishedAt: integer('source_scan_finished_at'),
		depScanFinishedAt: integer('dep_scan_finished_at')
	},
	(t) => [index('scans_created_idx').on(t.createdAt)]
);

export const findings = sqliteTable(
	'findings',
	{
		id: text('id').primaryKey(),
		scanId: text('scan_id')
			.notNull()
			.references(() => scans.id, { onDelete: 'cascade' }),
		phase: text('phase').notNull().default('A'),
		matchKey: text('match_key').notNull().default(''),
		ruleId: text('rule_id').notNull(),
		title: text('title').notNull(),
		severity: text('severity').notNull(),
		category: text('category').notNull(),
		description: text('description').notNull(),
		remediation: text('remediation').notNull(),
		confidence: text('confidence').notNull(),
		filePath: text('file_path').notNull(),
		line: integer('line'),
		excerpt: text('excerpt'),
		evidenceJson: text('evidence_json').notNull().default('[]'),
		verificationStatus: text('verification_status'),
		verifiedSnippet: text('verified_snippet'),
		verifiedAt: integer('verified_at'),
		fixPrompt: text('fix_prompt').notNull()
	},
	(t) => [index('findings_scan_idx').on(t.scanId), index('findings_scan_phase_idx').on(t.scanId, t.phase)]
);

export type ScanRow = typeof scans.$inferSelect;
export type FindingRow = typeof findings.$inferSelect;
