<script lang="ts">
	import { resolve } from '$app/paths';

	let { data } = $props();

	function fmtTime(ms: number) {
		return new Date(ms).toLocaleString();
	}
</script>

<svelte:head>
	<title>Kitscan</title>
</svelte:head>

<div class="page">
	<header class="hero">
		<h1>Kitscan - Security Audit Scanner</h1>
		<p class="lede">Run guided two-phase scans and review confirmed findings.</p>
		<a class="primary" href={resolve('/scans/new')}>New Scan</a>
	</header>

	<section class="panel">
		<h2>Recent scans</h2>
		{#if data.scans.length === 0}
			<p class="muted">No scans yet.</p>
		{:else}
			<ul class="list">
				{#each data.scans as s (s.id)}
					<li>
						<a href={resolve(`/scans/${s.id}`)} class="scan-link">
							<span class="id">{s.id.slice(0, 8)}…</span>
							<span class="status" data-status={s.status}>{s.status}</span>
							<span class="muted">{fmtTime(s.createdAt)}</span>
						</a>
						<div class="path" title={s.sourcePath}>{s.sourcePath}</div>
					</li>
				{/each}
			</ul>
		{/if}
	</section>
</div>

<style>
	.page {
		max-width: 54rem;
		margin: 0 auto;
		padding: 2rem 1.25rem 4rem;
	}

	.hero {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 1.2rem 1.3rem;
		margin-bottom: 1rem;
		text-align: center;
	}

	.hero h1 {
		margin: 0 0 0.5rem;
		font-size: 1.7rem;
	}

	.lede {
		margin: 0 0 0.9rem;
		color: var(--muted);
	}

	.primary {
		display: inline-block;
		background: var(--accent);
		border: 1px solid var(--accent-dim);
		color: white;
		text-decoration: none;
		border-radius: 6px;
		padding: 0.45rem 0.85rem;
		font-weight: 600;
	}

	.panel {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 1rem 1.15rem;
	}

	.panel h2 {
		margin: 0 0 0.75rem;
		font-size: 0.95rem;
	}

	.muted {
		color: var(--muted);
	}

	.list {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.list li {
		border-top: 1px solid var(--border);
		padding: 0.65rem 0;
	}

	.list li:first-child {
		border-top: none;
		padding-top: 0;
	}

	.scan-link {
		display: flex;
		gap: 0.6rem 0.9rem;
		align-items: baseline;
		text-decoration: none;
		color: var(--text);
	}

	.id {
		font-family: ui-monospace, monospace;
		font-size: 0.85rem;
	}

	.status {
		font-size: 0.75rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 0.12rem 0.45rem;
		border-radius: 4px;
		background: var(--border);
	}

	.status[data-status='completed'] {
		background: rgba(34, 197, 94, 0.2);
		color: #86efac;
	}

	.status[data-status='failed'] {
		background: rgba(248, 113, 113, 0.2);
		color: #fca5a5;
	}

	.status[data-status='running'] {
		background: rgba(61, 139, 253, 0.2);
		color: #93c5fd;
	}

	.path {
		font-size: 0.8rem;
		color: var(--muted);
		margin-top: 0.25rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>
