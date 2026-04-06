import { desc } from 'drizzle-orm';
import { scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async () => {
	const rows = getDb().select().from(scans).orderBy(desc(scans.createdAt)).limit(40).all();
	return { scans: rows };
};
