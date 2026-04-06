import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	optimizeDeps: { exclude: ['better-sqlite3'] },
	ssr: { external: ['better-sqlite3'], noExternal: [] }
});
