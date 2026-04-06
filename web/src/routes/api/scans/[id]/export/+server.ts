import { error, type RequestHandler } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { findings, scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import { exportJson, exportMarkdown } from '$lib/server/export';

export const GET: RequestHandler = async ({ params, url }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const format = url.searchParams.get('format') ?? 'json';
	const db = getDb();
	const scan = db.select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	const rows = db.select().from(findings).where(eq(findings.scanId, id)).all();

	if (format === 'md' || format === 'markdown') {
		const body = exportMarkdown(scan, rows);
		return new Response(body, {
			headers: {
				'Content-Type': 'text/markdown; charset=utf-8',
				'Content-Disposition': `attachment; filename="scan-${id}.md"`
			}
		});
	}

	const body = exportJson(scan, rows);
	return new Response(body, {
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			'Content-Disposition': `attachment; filename="scan-${id}.json"`
		}
	});
};
