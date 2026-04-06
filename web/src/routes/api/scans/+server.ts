import { json, type RequestHandler } from '@sveltejs/kit';
import { desc, eq } from 'drizzle-orm';
import { scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import { executeAssessment, resolveSourceRoot } from '$lib/server/scanner';

export const GET: RequestHandler = async () => {
	const rows = getDb().select().from(scans).orderBy(desc(scans.createdAt)).limit(50).all();
	return json({ scans: rows });
};

export const POST: RequestHandler = async ({ request }) => {
	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return json({ error: 'Invalid JSON body' }, { status: 400 });
	}

	const sourcePath =
		typeof body === 'object' && body !== null && 'sourcePath' in body
			? String((body as { sourcePath?: unknown }).sourcePath ?? '')
			: '';
	const runAssessment =
		typeof body === 'object' && body !== null && 'runAssessment' in body
			? Boolean((body as { runAssessment?: unknown }).runAssessment)
			: true;
	const resolved = resolveSourceRoot(sourcePath);
	if (!resolved.ok) {
		return json({ error: resolved.error }, { status: 400 });
	}

	const id = crypto.randomUUID();
	const now = Date.now();
	getDb()
		.insert(scans)
		.values({
			id,
			createdAt: now,
			sourcePath: resolved.path,
			status: 'pending',
			stepsJson: '[]',
			errorMessage: null,
			finishedAt: null,
			assessmentFinishedAt: null,
			sourceScanFinishedAt: null
		})
		.run();

	if (runAssessment) {
		queueMicrotask(() => {
			void executeAssessment(id);
		});
	}

	const scan = getDb().select().from(scans).where(eq(scans.id, id)).get();
	return json({ id, scan });
};
