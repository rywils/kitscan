import { json, error, type RequestHandler } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import { executeSourceScan } from '$lib/server/scanner';

export const POST: RequestHandler = async ({ params, request }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const body = await request.json().catch(() => ({}));
	const allowWithoutAssessment =
		typeof body === 'object' && body !== null && 'allowWithoutAssessment' in body
			? Boolean((body as { allowWithoutAssessment?: unknown }).allowWithoutAssessment)
			: false;
	const db = getDb();
	const scan = db.select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	if (!scan.assessmentFinishedAt && !allowWithoutAssessment) throw error(400, 'Run Phase A first');
	if (scan.status === 'running') return json({ ok: true, queued: false, message: 'Scan already running' });

	queueMicrotask(() => {
		void executeSourceScan(id);
	});
	return json({ ok: true, queued: true });
};
