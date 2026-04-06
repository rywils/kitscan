<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { onDestroy } from 'svelte';
	import { referencesFor, referencesToMarkdown, type HighImpactMode } from '$lib/references';
	import { resolve } from '$app/paths';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let sourceLoading = $state(false);
	let verifyLoading = $state(false);
	let deleteLoading = $state(false);
	let phaseErr = $state<string | null>(null);
	let copyMsg = $state<string | null>(null);
	let logCollapsed = $state(false);
	let selectedFinal = $state<string | null>(null);
	let chartMode = $state<'pie' | 'bar'>('pie');
	let highImpactMode = $state<HighImpactMode>('high-critical-only');
	let chartCanvas = $state<HTMLCanvasElement | null>(null);
	let severityChart: { destroy: () => void } | null = null;

	const steps = $derived.by(() => {
		try {
			return JSON.parse(data.scan.stepsJson || '[]') as { message: string; level: string; t: number }[];
		} catch {
			return [];
		}
	});

	const phaseA = $derived(data.findings.filter((f) => f.phase === 'A'));
	const phaseB = $derived(data.findings.filter((f) => f.phase === 'B'));

	const phaseAKeys = $derived(new Set(phaseA.map((f) => f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const phaseBKeys = $derived(new Set(phaseB.map((f) => f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));

	const falsePositives = $derived(phaseA.filter((f) => !phaseBKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const missedByA = $derived(phaseB.filter((f) => !phaseAKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const confirmed = $derived(phaseB.filter((f) => phaseAKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const finalFindings = $derived([...confirmed, ...missedByA]);
	const severityCounts = $derived.by(() => {
		const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
		for (const f of finalFindings) {
			counts[f.severity] = (counts[f.severity] ?? 0) + 1;
		}
		return counts;
	});

	$effect(() => {
		const canvas = chartCanvas;
		if (!canvas) return;
		const values = [severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low, severityCounts.info];
		if (severityChart) {
			severityChart.destroy();
			severityChart = null;
		}
		void import('chart.js/auto').then((mod) => {
			const ChartCtor = mod.default;
			severityChart = new ChartCtor(canvas, {
				type: chartMode,
				data: {
					labels: ['critical', 'high', 'medium', 'low', 'info'],
					datasets: [
						{
							data: values,
							backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#475569', '#64748b']
						}
					]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					plugins: {
						legend: chartMode === 'pie' ? { labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 10 } } } : { display: false }
					},
					scales: chartMode === 'bar' ? {
						x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.14)' } },
						y: { ticks: { color: '#94a3b8', precision: 0, font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.14)' }, beginAtZero: true }
					} : undefined
				}
			});
		});
	});

	onDestroy(() => {
		if (severityChart) severityChart.destroy();
	});
	const selected = $derived(selectedFinal ? finalFindings.find((f) => f.id === selectedFinal) ?? null : finalFindings[0] ?? null);
	const selectedReferences = $derived(selected ? referencesFor(selected.ruleId, selected.category, selected.severity, { highImpactMode }) : []);
	const phaseACompleted = $derived(!!data.scan.assessmentFinishedAt);
	const phaseBCompleted = $derived(!!data.scan.sourceScanFinishedAt);
	const phaseARunning = $derived(data.scan.status === 'running' && !data.scan.assessmentFinishedAt);
	const phaseBRunning = $derived(data.scan.status === 'running' && !!data.scan.assessmentFinishedAt && !data.scan.sourceScanFinishedAt);

	const phaseAButtonLabel = $derived(phaseACompleted ? 'Completed Phase A' : phaseARunning ? 'Running...' : 'Run Phase A');
	const phaseBButtonLabel = $derived(phaseBCompleted ? 'Completed Phase B' : phaseBRunning ? 'Running...' : 'Run Phase B');
	const phaseAButtonClass = $derived(phaseACompleted ? 'phase-action complete' : phaseARunning ? 'phase-action running' : 'phase-action ready');
	const phaseBButtonClass = $derived(phaseBCompleted ? 'phase-action complete' : phaseBRunning ? 'phase-action running' : 'phase-action ready');

	async function runPhaseA() {
		phaseErr = null;
		if (phaseARunning || phaseACompleted) return;
		sourceLoading = false;
		try {
			const res = await fetch(resolve(`/api/scans/${data.scan.id}/assessment`), { method: 'POST' });
			const body = await res.json().catch(() => ({}));
			if (!res.ok) {
				phaseErr = typeof body.error === 'string' ? body.error : res.statusText;
				return;
			}
			await waitForPhase('A');
		} catch (e) {
			phaseErr = e instanceof Error ? e.message : 'Phase A failed';
		}
	}

	async function runSourceScan() {
		phaseErr = null;
		sourceLoading = true;
		try {
			const res = await fetch(resolve(`/api/scans/${data.scan.id}/source-scan`), { method: 'POST' });
			const body = await res.json().catch(() => ({}));
			if (!res.ok) {
				phaseErr = typeof body.error === 'string' ? body.error : res.statusText;
				return;
			}
			await waitForPhase('B');
		} catch (e) {
			phaseErr = e instanceof Error ? e.message : 'Source scan failed';
		} finally {
			sourceLoading = false;
		}
	}

	async function waitForPhase(phase: 'A' | 'B') {
		for (let i = 0; i < 240; i++) {
			await new Promise((r) => setTimeout(r, 500));
			await invalidateAll();
			const doneA = !!data.scan.assessmentFinishedAt && data.scan.status !== 'running';
			const doneB = !!data.scan.sourceScanFinishedAt && data.scan.status !== 'running';
			if (data.scan.status === 'failed') break;
			if ((phase === 'A' && doneA) || (phase === 'B' && doneB)) break;
		}
	}

	async function verifySource() {
		phaseErr = null;
		verifyLoading = true;
		try {
			const res = await fetch(resolve(`/api/scans/${data.scan.id}/verify`), { method: 'POST' });
			const body = await res.json().catch(() => ({}));
			if (!res.ok) {
				phaseErr = typeof body.error === 'string' ? body.error : res.statusText;
				return;
			}
			await invalidateAll();
		} catch (e) {
			phaseErr = e instanceof Error ? e.message : 'Verify failed';
		} finally {
			verifyLoading = false;
		}
	}

	async function deleteScan() {
		if (!confirm('Delete this scan and all findings?')) return;
		deleteLoading = true;
		try {
			const res = await fetch(resolve(`/api/scans/${data.scan.id}`), { method: 'DELETE' });
			if (res.ok) window.location.href = '/';
		} finally {
			deleteLoading = false;
		}
	}

	async function copyPrompt(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copyMsg = 'Copied';
			setTimeout(() => (copyMsg = null), 1500);
		} catch {
			copyMsg = 'Copy failed';
		}
	}

	async function copyReferences() {
		if (!selected || selectedReferences.length === 0) return;
		const blob = `Research references for ${selected.title}\n\n${referencesToMarkdown(selectedReferences)}\n\nHigh-impact mode: ${highImpactMode}`;
		try {
			await navigator.clipboard.writeText(blob);
			copyMsg = 'References copied';
			setTimeout(() => (copyMsg = null), 1800);
		} catch {
			copyMsg = 'Copy failed';
		}
	}

	function sevClass(s: string) {
		return `sev sev-${s}`;
	}

	function phaseLabel(phase: 'A' | 'B') {
		if (phase === 'A') {
			if (data.scan.assessmentFinishedAt) return 'COMPLETE';
			if (data.scan.status === 'running') return 'Running...';
			return 'Pending';
		}
		if (data.scan.sourceScanFinishedAt) return 'COMPLETE';
		if (data.scan.status === 'running' && data.scan.assessmentFinishedAt) return 'Running...';
		return 'Pending';
	}

	function phaseClass(phase: 'A' | 'B') {
		const label = phaseLabel(phase);
		if (label === 'COMPLETE') return 'phase-pill complete';
		if (label === 'Running...') return 'phase-pill running';
		return 'phase-pill pending';
	}
</script>

<svelte:head><title>Scan {data.scan.id.slice(0, 8)}…</title></svelte:head>

<div class="page">
	<nav class="crumb">
		<a href={resolve('/')}>← Home</a>
		<a class="btn primary" href={resolve('/scans/new')}>New Scan</a>
	</nav>

	<header class="head">
		<div>
			<h1>Scan <code>{data.scan.id}</code></h1>
			<p class="path"><strong>Root:</strong> {data.scan.sourcePath}</p>
			<p class="path">
				<strong>Phase A:</strong> <span class={phaseClass('A')}>{phaseLabel('A')}</span> ·
				<strong>Phase B:</strong> <span class={phaseClass('B')}>{phaseLabel('B')}</span>
			</p>
		</div>
		<div class="toolbar">
			<button class="btn tip-target" data-tooltip="Runs a secondary verification pass against source files to confirm or downgrade findings." onclick={verifySource} disabled={verifyLoading || !data.scan.sourceScanFinishedAt}>{verifyLoading ? 'Verifying…' : 'Verify'}</button>
			<a class="btn tip-target" data-tooltip="Downloads this scan as structured JSON, including findings, diffs, and references." href={resolve(`/api/scans/${data.scan.id}/export?format=json`)}>Export JSON</a>
			<a class="btn tip-target" data-tooltip="Downloads this scan as Markdown report for sharing or documentation." href={resolve(`/api/scans/${data.scan.id}/export?format=md`)}>Export MD</a>
			<button class="btn danger tip-target" data-tooltip="Deletes this scan and all stored findings for it." onclick={deleteScan} disabled={deleteLoading}>Delete</button>
		</div>
	</header>

	{#if phaseErr}<p class="banner err">{phaseErr}</p>{/if}

	<section class="panel">
		<div class="log-head">
			<h2>Live scanner output</h2>
			<button class="btn small tip-target" data-tooltip="Toggles the live scanner output panel." onclick={() => (logCollapsed = !logCollapsed)}>{logCollapsed ? 'Expand' : 'Collapse'}</button>
		</div>
		{#if !logCollapsed}
			<div class="term-box">
				{#each steps as st, i (`${st.t}-${i}`)}
					<div class="line" data-level={st.level}>{st.message}</div>
				{/each}
			</div>
		{/if}
	</section>

	<div class="grid4">
		<section class="panel mini">
			<h3>Phase A results ({phaseA.length})</h3>
			<button class={`${phaseAButtonClass} tip-target`} data-tooltip="Phase A runs baseline rules and initial detection against the mounted directory." onclick={runPhaseA} disabled={phaseARunning || phaseACompleted}>{phaseAButtonLabel}</button>
			<div class="mini-list">{#each phaseA as f (f.id)}<div class="item"><span class={sevClass(f.severity)}>{f.severity}</span><span>{f.title}</span></div>{/each}</div>
		</section>
		<section class="panel mini">
			<h3>Phase B results ({phaseB.length})</h3>
			<button class={`${phaseBButtonClass} tip-target`} data-tooltip="Phase B runs deeper secondary scanning used for diffs and final confirmed results." onclick={runSourceScan} disabled={phaseBRunning || phaseBCompleted || !phaseACompleted}>{phaseBButtonLabel}</button>
			<div class="mini-list">{#each phaseB as f (f.id)}<div class="item"><span class={sevClass(f.severity)}>{f.severity}</span><span>{f.title}</span></div>{/each}</div>
		</section>
		<section class="panel mini">
			<h3>Differences</h3>
			<p class="muted">False positives from A: {falsePositives.length}</p>
			<p class="muted">Undetected in A (found in B): {missedByA.length}</p>
			<div class="chart-mode" role="radiogroup" aria-label="Severity chart mode">
				<label class="mode-opt">
					<input type="radio" name="chart-mode" value="pie" checked={chartMode === 'pie'} onchange={() => (chartMode = 'pie')} />
					<span>Pie</span>
				</label>
				<label class="mode-opt">
					<input type="radio" name="chart-mode" value="bar" checked={chartMode === 'bar'} onchange={() => (chartMode = 'bar')} />
					<span>Bar</span>
				</label>
			</div>
			<div class="chart-wrap">
				<canvas bind:this={chartCanvas} aria-label="Final severity distribution"></canvas>
			</div>
		</section>
		<section class="panel mini">
			<h3>Final (most accurate) ({finalFindings.length})</h3>
			<div class="mini-list">{#each finalFindings as f (f.id)}<button class="item pick" onclick={() => (selectedFinal = f.id)}><span class={sevClass(f.severity)}>{f.severity}</span><span>{f.title}</span></button>{/each}</div>
		</section>
	</div>

	<section class="panel">
		<h3>Final detail</h3>
		{#if !selected}
			<p class="muted">No final findings yet.</p>
		{:else}
			<p class="muted"><code>{selected.filePath}:{selected.line}</code></p>
			<p>{selected.description}</p>
			<p><strong>Fix:</strong> {selected.remediation}</p>
			{#if selectedReferences.length > 0}
				<div class="refs-head">
					<p><strong>Research references:</strong></p>
					<div class="refs-actions">
						<select class="refs-mode" bind:value={highImpactMode} aria-label="High impact references mode">
							<option value="high-critical-only">NIST/CISA: high/critical</option>
							<option value="always">NIST/CISA: always include</option>
							<option value="never">NIST/CISA: never include</option>
						</select>
						<button class="btn small tip-target" data-tooltip="Copies all current research references and rationale to your clipboard." onclick={copyReferences}>Copy references</button>
						<button
							class="btn small tip-target" data-tooltip="Opens every listed reference in new tabs after confirmation."
							onclick={() => {
								if (!confirm(`Open ${selectedReferences.length} references in new tabs?`)) return;
								for (const ref of selectedReferences) window.open(ref.url, '_blank', 'noopener,noreferrer');
							}}
						>
							Open all
						</button>
					</div>
				</div>
				<ul class="refs">
					{#each selectedReferences as ref (`${ref.url}`)}
						<li><a href={ref.url} target="_blank" rel="noreferrer">{ref.label}</a>{#if ref.reason}<span class="ref-reason"> - {ref.reason}</span>{/if}</li>
					{/each}
				</ul>
			{/if}
			{#if selected.verifiedSnippet}<pre class="snippet">{selected.verifiedSnippet}</pre>{/if}
			<div class="prompt-head"><span>Prompt</span><button class="btn small tip-target" data-tooltip="Copies the AI-ready remediation prompt for this finding." onclick={() => copyPrompt(selected.fixPrompt)}>Copy</button>{#if copyMsg}<span class="muted">{copyMsg}</span>{/if}</div>
			<pre class="snippet">{selected.fixPrompt}</pre>
		{/if}
	</section>

	<div class="bottom-actions">
		<a class="btn primary" href={resolve('/scans/new')}>New Scan</a>
	</div>
</div>

<style>
	.page { max-width: 80rem; margin: 0 auto; padding: 1rem 1rem 2rem; }
	.crumb { margin-bottom: 0.8rem; display: flex; justify-content: space-between; align-items: center; gap: 0.6rem; }
	.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.8rem 1rem; margin-bottom: 0.9rem; }
	.head { display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
	.toolbar { display: flex; gap: 0.45rem; flex-wrap: wrap; align-items: center; }
	.btn { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 6px; padding: 0.35rem 0.6rem; text-decoration: none; cursor: pointer; }
	.btn.primary { background: var(--accent); color: #fff; border-color: var(--accent-dim); }
	.btn.danger { color: #fca5a5; border-color: rgba(248, 113, 113, 0.6); }
	.btn.small { padding: 0.2rem 0.45rem; font-size: 0.78rem; }
	.banner.err { background: rgba(248,113,113,.15); color: #fecaca; border-radius: 6px; padding: 0.5rem 0.7rem; }
	.path { margin: 0.2rem 0; color: var(--muted); font-size: 0.86rem; }
	.log-head { display: flex; justify-content: space-between; align-items: center; }
	.term-box { max-height: 13rem; overflow: auto; background: #0a0c10; border: 1px solid var(--border); border-radius: 8px; padding: 0.55rem 0.65rem; font-family: ui-monospace, monospace; font-size: 0.78rem; }
	.line { white-space: pre-wrap; }
	.line[data-level='warn'] { color: #fde68a; }
	.line[data-level='error'] { color: #fecaca; }
	.grid4 { display: grid; grid-template-columns: repeat(1, minmax(0, 1fr)); gap: 0.75rem; }
	@media (min-width: 1100px) { .grid4 { grid-template-columns: repeat(4, minmax(0, 1fr)); } }
	.mini h3 { margin: 0 0 0.5rem; font-size: 0.9rem; }
	.mini-list { max-height: 13rem; overflow: auto; display: grid; gap: 0.3rem; }
	.item { display: grid; grid-template-columns: auto 1fr; gap: 0.4rem; align-items: center; font-size: 0.8rem; }
	.pick { text-align: left; background: transparent; border: 1px solid transparent; border-radius: 6px; padding: 0.22rem; }
	.pick:hover { border-color: var(--border); }
	.sev { font-size: 0.66rem; text-transform: uppercase; padding: 0.1rem 0.35rem; border-radius: 4px; }
	.sev-critical { background: rgba(220,38,38,.35); color: #fecaca; }
	.sev-high { background: rgba(234,88,12,.35); color: #fed7aa; }
	.sev-medium { background: rgba(202,138,4,.35); color: #fef08a; }
	.sev-low,.sev-info { background: var(--border); color: var(--muted); }
	.muted { color: var(--muted); }
	.snippet { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem; font-size: 0.8rem; white-space: pre-wrap; overflow: auto; }
	.refs-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; margin-top: 0.35rem; }
	.refs-head p { margin: 0; }
	.refs-actions { display: inline-flex; gap: 0.35rem; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
	.refs-mode { background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 0.2rem 0.35rem; font-size: 0.75rem; }
	.refs { margin: 0.15rem 0 0.6rem 1rem; padding: 0; }
	.refs li { margin: 0.15rem 0; font-size: 0.84rem; }
	.ref-reason { color: var(--muted); font-size: 0.78rem; }
	.refs a { color: #93c5fd; }
	.refs a:hover { color: #bfdbfe; }
	.prompt-head { display: flex; justify-content: space-between; align-items: center; margin: 0.6rem 0 0.3rem; }
	.chart-wrap { margin-top: 0.55rem; height: 140px; }
	.phase-pill { display: inline-block; border-radius: 4px; padding: 0.05rem 0.36rem; font-size: 0.72rem; margin-left: 0.22rem; }
	.phase-pill.complete { color: #22c55e; font-weight: 800; text-transform: uppercase; }
	.phase-pill.running { color: #94a3b8; font-weight: 500; text-transform: none; }
	.phase-pill.pending { color: var(--muted); font-weight: 500; text-transform: none; }
	.chart-mode { margin-top: 0.35rem; display: flex; gap: 0.45rem; align-items: center; }
	.mode-opt { display: inline-flex; align-items: center; gap: 0.3rem; border: 1px solid var(--border); border-radius: 999px; padding: 0.12rem 0.45rem; font-size: 0.76rem; color: var(--muted); cursor: pointer; }
	.mode-opt input { accent-color: var(--accent); }
	.phase-action { margin: 0.2rem 0 0.6rem; width: 100%; border: none; border-radius: 8px; padding: 0.5rem 0.7rem; font-weight: 800; letter-spacing: 0.01em; cursor: pointer; }
	.phase-action.ready { background: #dc2626; color: #fff; }
	.phase-action.running { background: #4b5563; color: #e5e7eb; font-weight: 700; }
	.phase-action.complete { background: #16a34a; color: #fff; }
	.phase-action:disabled { cursor: not-allowed; }
	.bottom-actions { margin-top: 0.9rem; display: flex; justify-content: center; }
</style>
