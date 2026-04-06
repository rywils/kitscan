import { extname } from 'node:path';

/** Extensions scanned as UTF-8 text (bounded size elsewhere). */
export const TEXT_EXTENSIONS = new Set([
	'.ts',
	'.tsx',
	'.js',
	'.jsx',
	'.mjs',
	'.cjs',
	'.svelte',
	'.vue',
	'.py',
	'.go',
	'.rb',
	'.php',
	'.java',
	'.kt',
	'.rs',
	'.env',
	'.env.local',
	'.env.development',
	'.env.production',
	'.json',
	'.yaml',
	'.yml',
	'.sql',
	'.md',
	'.html',
	'.css',
	'.scss',
	'.toml'
]);

export const SKIP_DIR_NAMES = new Set([
	'node_modules',
	'.git',
	'dist',
	'build',
	'.svelte-kit',
	'.next',
	'coverage',
	'.nuxt',
	'.output',
	'target',
	'vendor',
	'__pycache__',
	'.venv',
	'venv'
]);

export const MAX_FILE_BYTES = 512 * 1024;
export const MAX_FILES = 8000;
export const MAX_DEPTH = 14;

export function isTextFile(relPath: string): boolean {
	const ext = extname(relPath).toLowerCase();
	if (TEXT_EXTENSIONS.has(ext)) return true;
	// Files named .env* without normal ext
	const base = relPath.split('/').pop() ?? '';
	if (base.startsWith('.env')) return true;
	return false;
}

/** Heuristic: code likely shipped to browser / user-visible bundle. */
export function looksLikeClientPath(relPath: string): boolean {
	const p = relPath.replace(/\\/g, '/').toLowerCase();
	if (p.includes('/server/')) return false;
	if (p.includes('/api/') && !p.includes('client')) return false;
	return (
		p.includes('/client/') ||
		p.includes('/components/') ||
		p.includes('/src/routes/') ||
		p.includes('/app/') ||
		p.includes('/pages/') ||
		p.includes('/lib/') ||
		p.includes('/hooks/') ||
		p.endsWith('.svelte') ||
		p.endsWith('.vue')
	);
}
