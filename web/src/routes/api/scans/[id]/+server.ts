import { json, error, type RequestHandler } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { findings, scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';

export const GET: RequestHandler = async ({ params }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const scan = getDb().select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	const rows = getDb().select().from(findings).where(eq(findings.scanId, id)).all();
	return json({ scan, findings: rows });
};

export const DELETE: RequestHandler = async ({ params }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const db = getDb();
	const scan = db.select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	db.delete(findings).where(eq(findings.scanId, id)).run();
	db.delete(scans).where(eq(scans.id, id)).run();
	return json({ ok: true });
};
