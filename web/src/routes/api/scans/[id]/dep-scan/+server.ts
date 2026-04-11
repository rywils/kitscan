import { json, error, type RequestHandler } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import { executeDepScan } from '$lib/server/scanner';

export const POST: RequestHandler = async ({ params }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const db = getDb();
	const scan = db.select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	if (scan.status === 'running') return json({ ok: true, queued: false, message: 'Scan already running' });

	queueMicrotask(() => {
		void executeDepScan(id);
	});
	return json({ ok: true, queued: true });
};
