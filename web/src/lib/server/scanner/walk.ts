import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { isTextFile, MAX_DEPTH, MAX_FILE_BYTES, MAX_FILES, SKIP_DIR_NAMES } from './constants';

export type FileEntry = { absPath: string; relPath: string };

export function collectTextFiles(rootAbs: string): { files: FileEntry[]; truncated: boolean } {
	const root = rootAbs.replace(/\/$/, '');
	const files: FileEntry[] = [];
	let truncated = false;

	const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];

	while (stack.length > 0) {
		const { dir, depth } = stack.pop()!;
		if (depth > MAX_DEPTH) {
			truncated = true;
			continue;
		}
		let names: string[];
		try {
			names = readdirSync(dir);
		} catch {
			continue;
		}
		for (const name of names) {
			if (files.length >= MAX_FILES) {
				truncated = true;
				return { files, truncated };
			}
			const abs = join(dir, name);
			let st;
			try {
				st = statSync(abs);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				if (SKIP_DIR_NAMES.has(name)) continue;
				stack.push({ dir: abs, depth: depth + 1 });
			} else if (st.isFile()) {
				const relPath = relative(root, abs).split(sep).join('/');
				if (!relPath || relPath.startsWith('..')) continue;
				if (!isTextFile(relPath)) continue;
				if (st.size > MAX_FILE_BYTES) continue;
				files.push({ absPath: abs, relPath });
			}
		}
	}

	return { files, truncated };
}

export function readUtf8File(absPath: string): string | null {
	try {
		return readFileSync(absPath, 'utf8');
	} catch {
		return null;
	}
}
