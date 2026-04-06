import { json, error, type RequestHandler } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { findings, scans } from '$lib/server/db/schema';
import { getDb } from '$lib/server/db';
import { resolveSourceRoot } from '$lib/server/scanner';
import { verifyFinding } from '$lib/server/scanner/verify';

export const POST: RequestHandler = async ({ params, request }) => {
	const id = params.id;
	if (!id) throw error(400, 'Missing scan id');
	const db = getDb();
	const scan = db.select().from(scans).where(eq(scans.id, id)).get();
	if (!scan) throw error(404, 'Scan not found');

	let overridePath: string | undefined;
	try {
		const body = await request.json();
		if (body && typeof body === 'object' && 'sourcePath' in body) {
			const p = String((body as { sourcePath?: unknown }).sourcePath ?? '').trim();
			if (p) overridePath = p;
		}
	} catch {
		/* optional body */
	}

	const pathToUse = overridePath ?? scan.sourcePath;
	const resolved = resolveSourceRoot(pathToUse);
	if (!resolved.ok) {
		return json({ error: resolved.error }, { status: 400 });
	}

	if (!scan.sourceScanFinishedAt) {
		return json({ error: 'Run Source scan (Phase B) before verification.' }, { status: 400 });
	}

	const rows = db.select().from(findings).where(eq(findings.scanId, id)).all();
	const now = Date.now();
	let updated = 0;

	for (const f of rows) {
		const { status, verifiedSnippet, fixPrompt } = verifyFinding(resolved.path, f);
		db.update(findings)
			.set({
				verificationStatus: status,
				verifiedSnippet,
				verifiedAt: now,
				fixPrompt
			})
			.where(eq(findings.id, f.id))
			.run();
		updated++;
	}

	return json({ ok: true, updated, sourcePath: resolved.path });
};
