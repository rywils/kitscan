import { error } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { findings, scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ params }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing id');
	const scan = getDb().select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');
	const rows = getDb().select().from(findings).where(eq(findings.scanId, id)).all();
	return { scan, findings: rows };
};
