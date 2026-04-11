<script lang="ts">
	import { browser } from '$app/environment';
	import { resolve } from '$app/paths';
	import { referencesFor, referencesToMarkdown, type HighImpactMode } from '$lib/references';
	import { onDestroy } from 'svelte';

	type ScanRow = {
		id: string;
		createdAt: number;
		sourcePath: string;
		status: string;
		stepsJson: string;
		errorMessage: string | null;
		assessmentFinishedAt: number | null;
		sourceScanFinishedAt: number | null;
		depScanFinishedAt: number | null;
	};

	type Finding = {
		id: string;
		phase: 'A' | 'B' | 'D';
		ruleId: string;
		title: string;
		severity: string;
		category: string;
		filePath: string;
		line: number | null;
		description: string;
		remediation: string;
		fixPrompt: string;
		matchKey: string;
	};

type FindingSummary = {
	key: string;
	severity: string;
	title: string;
	count: number;
	firstId: string;
	locations: Array<{ label: string; count: number }>;
};

	let sourcePath = $state('');
	let mountLoading = $state(false);
	let mounted = $state(false);
	let err = $state<string | null>(null);
	let scanId = $state<string | null>(null);
	let scan = $state<ScanRow | null>(null);
	let findings = $state<Finding[]>([]);
	let logs = $state<string[]>([]);
	let logPhase = $state<'A' | 'B' | 'D'>('A');
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let selectedFinal = $state<string | null>(null);
	let chartMode = $state<'pie' | 'bar'>('pie');
	let chartCanvas = $state<HTMLCanvasElement | null>(null);
	let severityChart: any = null;
	let chartLib: (typeof import('chart.js')) | null = null;
	let lastChartKey = $state('');
	let lastChartMode = $state<'pie' | 'bar' | null>(null);
	let highImpactMode = $state<HighImpactMode>('high-critical-only');
	let copyMsg = $state<string | null>(null);
	let promptCopyMsg = $state<string | null>(null);
	let viewMode = $state<'combined' | 'a-only' | 'b-only'>('combined');
	let runAllLoading = $state(false);

	const phaseA = $derived(findings.filter((f) => f.phase === 'A'));
	const phaseB = $derived(findings.filter((f) => f.phase === 'B'));
	const phaseD = $derived(findings.filter((f) => f.phase === 'D'));

	const phaseAKeys = $derived(new Set(phaseA.map((f) => f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const phaseBKeys = $derived(new Set(phaseB.map((f) => f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const falsePositives = $derived(phaseA.filter((f) => !phaseBKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const missedByA = $derived(phaseB.filter((f) => !phaseAKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const confirmed = $derived(phaseB.filter((f) => phaseAKeys.has(f.matchKey || `${f.ruleId}|${f.filePath}|${f.line}|${f.title}`)));
	const combinedFinalFindings = $derived([...confirmed, ...missedByA, ...phaseD]);
	const activeMode = $derived(viewMode === 'a-only' ? 'A' : viewMode === 'b-only' ? 'B' : 'combined');
	const finalFindings = $derived(activeMode === 'A' ? phaseA : activeMode === 'B' ? phaseB : combinedFinalFindings);
	const selected = $derived(selectedFinal ? finalFindings.find((f) => f.id === selectedFinal) ?? null : finalFindings[0] ?? null);
	const selectedReferences = $derived(
		selected ? referencesFor(selected.ruleId, selected.category, selected.severity, { highImpactMode }) : []
	);
	const severityCounts = $derived.by(() => {
		const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
		for (const f of finalFindings) {
			const sev = f.severity.toLowerCase();
			if (sev in counts) counts[sev as keyof typeof counts] += 1;
		}
		return counts;
	});

	function summarizeFindings(items: Finding[]): FindingSummary[] {
		const grouped = new Map<string, FindingSummary>();
		for (const f of items) {
			const key = `${f.severity.toLowerCase()}|${f.title}`;
			const row = grouped.get(key);
			if (row) {
				row.count += 1;
				const loc = `${f.filePath}${f.line != null ? `:${f.line}` : ''}`;
				const existing = row.locations.find((l) => l.label === loc);
				if (existing) existing.count += 1;
				else row.locations.push({ label: loc, count: 1 });
				continue;
			}
			const loc = `${f.filePath}${f.line != null ? `:${f.line}` : ''}`;
			grouped.set(key, {
				key,
				severity: f.severity,
				title: f.title,
				count: 1,
				firstId: f.id,
				locations: [{ label: loc, count: 1 }]
			});
		}
		const order = ['critical', 'high', 'medium', 'low', 'info'];
		return [...grouped.values()].sort((a, b) => {
			const ai = order.indexOf(a.severity.toLowerCase());
			const bi = order.indexOf(b.severity.toLowerCase());
			if (ai !== bi) return ai - bi;
			return a.title.localeCompare(b.title);
		});
	}

	const phaseASummary = $derived(summarizeFindings(phaseA));
	const phaseBSummary = $derived(summarizeFindings(phaseB));
	const phaseDSummary = $derived(summarizeFindings(phaseD));
	const finalSummary = $derived(summarizeFindings(finalFindings));

	const phaseAState = $derived.by(() => {
		if (!scan) return 'idle';
		if (scan.assessmentFinishedAt) return 'done';
		if (scan.status === 'running' && !scan.assessmentFinishedAt) return 'running';
		return 'ready';
	});

	const phaseBState = $derived.by(() => {
		if (!scan) return 'idle';
		if (scan.sourceScanFinishedAt) return 'done';
		if (scan.status === 'running' && !!scan.assessmentFinishedAt && !scan.sourceScanFinishedAt) return 'running';
		if (!scan.assessmentFinishedAt && viewMode !== 'b-only') return 'idle';
		return 'ready';
	});

	const phaseAButtonLabel = $derived(
		phaseAState === 'done' ? 'Completed Light Scan' : phaseAState === 'running' ? 'Running...' : 'Run Light Scan'
	);
	const phaseBButtonLabel = $derived(
		phaseBState === 'done' ? 'Completed Deep Scan' : phaseBState === 'running' ? 'Running...' : 'Run Deep Scan'
	);

	const phaseDState = $derived.by(() => {
		if (!scan) return 'idle';
		if (scan.depScanFinishedAt) return 'done';
		if (scan.status === 'running' && !scan.depScanFinishedAt) return 'running';
		return 'ready';
	});
	const phaseDButtonLabel = $derived(
		phaseDState === 'done' ? 'Completed Dep Scan' : phaseDState === 'running' ? 'Running...' : 'Run Dep Scan'
	);

	const phaseABar = $derived(phaseAState === 'done' ? 100 : phaseAState === 'running' ? 60 : 0);
	const phaseBBar = $derived(phaseBState === 'done' ? 100 : phaseBState === 'running' ? 60 : 0);
	const phaseDBar = $derived(phaseDState === 'done' ? 100 : phaseDState === 'running' ? 60 : 0);
	const phaseABarClass = $derived(phaseABar === 100 ? 'bar-100' : phaseABar === 60 ? 'bar-60' : 'bar-0');
	const phaseBBarClass = $derived(phaseBBar === 100 ? 'bar-100' : phaseBBar === 60 ? 'bar-60' : 'bar-0');
	const phaseDBarClass = $derived(phaseDBar === 100 ? 'bar-100' : phaseDBar === 60 ? 'bar-60' : 'bar-0');

	const showPhaseAResults = $derived(phaseAState === 'running' || phaseAState === 'done');
	const showPhaseBResults = $derived(phaseBState === 'running' || phaseBState === 'done');
	const showPhaseDResults = $derived(phaseDState === 'running' || phaseDState === 'done');
	const showDiffs = $derived(activeMode === 'combined' && (phaseBState === 'running' || phaseBState === 'done'));
	const showChart = $derived(
		(activeMode === 'combined' && (phaseBState === 'done' || phaseDState === 'done')) ||
		(activeMode === 'B' && (phaseBState === 'running' || phaseBState === 'done'))
	);
	const showFinal = $derived(
		(activeMode === 'A' && (phaseAState === 'running' || phaseAState === 'done')) ||
			(activeMode === 'B' && (phaseBState === 'running' || phaseBState === 'done')) ||
			(activeMode === 'combined' && (phaseBState === 'done' || phaseDState === 'done'))
	);
	const showHydratedReport = $derived(showFinal);

	function stopPolling() {
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = null;
		}
	}

	function applyLogView(allSteps: { message: string }[]) {
		const msgs = allSteps.map((s) => s.message);
		if (logPhase === 'B') {
			logs = msgs.filter((m) => m.includes('[Phase B]')).slice(-300);
		} else if (logPhase === 'D') {
			logs = msgs.filter((m) => m.includes('[Phase D]')).slice(-300);
		} else {
			logs = msgs.slice(-300);
		}
	}

	async function refreshScan() {
		if (!scanId) return;
		const res = await fetch(resolve(`/api/scans/${scanId}`));
		if (!res.ok) return;
		const body = await res.json();
		scan = body.scan as ScanRow;
		findings = (body.findings as Finding[]) ?? [];
		try {
			const steps = JSON.parse(scan?.stepsJson || '[]') as { message: string }[];
			applyLogView(steps);
		} catch {
			logs = [];
		}
	}

	function ensurePolling() {
		stopPolling();
		pollTimer = setInterval(() => {
			void refreshScan();
		}, 700);
	}

	async function mountDirectory(e: Event) {
		e.preventDefault();
		err = null;
		mountLoading = true;
		try {
			const res = await fetch(resolve('/api/scans'), {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ sourcePath: sourcePath.trim(), runAssessment: false })
			});
			const body = await res.json().catch(() => ({}));
			if (!res.ok) {
				err = typeof body.error === 'string' ? body.error : res.statusText;
				return;
			}
			mounted = true;
			scanId = body.id as string;
			logPhase = 'A';
			await refreshScan();
			ensurePolling();
		} catch (e) {
			err = e instanceof Error ? e.message : 'Request failed';
		} finally {
			mountLoading = false;
		}
	}

	async function runPhaseA() {
		if (!scanId || phaseAState === 'running' || phaseAState === 'done') return;
		logPhase = 'A';
		await fetch(resolve(`/api/scans/${scanId}/assessment`), { method: 'POST' });
		await refreshScan();
	}

	async function runPhaseB() {
		if (!scanId || phaseBState === 'running' || phaseBState === 'done' || (!scan?.assessmentFinishedAt && viewMode !== 'b-only')) return;
		logPhase = 'B';
		logs = [];
		await fetch(resolve(`/api/scans/${scanId}/source-scan`), {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ allowWithoutAssessment: viewMode === 'b-only' })
		});
		await refreshScan();
	}

	async function runDepScanPhase() {
		if (!scanId || phaseDState === 'running' || phaseDState === 'done') return;
		logPhase = 'D';
		logs = [];
		await fetch(resolve(`/api/scans/${scanId}/dep-scan`), { method: 'POST' });
		await refreshScan();
	}

	async function waitForCompletion(check: () => boolean, timeoutMs = 15 * 60 * 1000) {
		const start = Date.now();
		while (Date.now() - start < timeoutMs) {
			await refreshScan();
			if (check()) return true;
			if (scan?.status === 'failed') return false;
			await new Promise((r) => setTimeout(r, 700));
		}
		return false;
	}

	async function runAllPhases() {
		if (!scanId || runAllLoading || phaseAState === 'running' || phaseBState === 'running' || phaseDState === 'running') return;
		runAllLoading = true;
		err = null;
		try {
			if (!scan?.assessmentFinishedAt) {
				await runPhaseA();
				const okA = await waitForCompletion(() => !!scan?.assessmentFinishedAt);
				if (!okA) return;
			}
			if (!scan?.sourceScanFinishedAt) {
				await runPhaseB();
				await waitForCompletion(() => !!scan?.sourceScanFinishedAt);
			}
			if (!scan?.depScanFinishedAt) {
				await runDepScanPhase();
				await waitForCompletion(() => !!scan?.depScanFinishedAt);
			}
		} finally {
			runAllLoading = false;
		}
	}

	function startNewScan() {
		stopPolling();
		sourcePath = '';
		mountLoading = false;
		mounted = false;
		err = null;
		scanId = null;
		scan = null;
		findings = [];
		logs = [];
		logPhase = 'A';
		selectedFinal = null;
		chartMode = 'pie';
		lastChartKey = '';
		lastChartMode = null;
		viewMode = 'combined';
		runAllLoading = false;
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}

	function phaseClass(state: string) {
		if (state === 'done') return 'phase-btn done';
		if (state === 'running') return 'phase-btn running';
		return 'phase-btn ready';
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

	async function copyPrompt(value: string) {
		try {
			await navigator.clipboard.writeText(value);
			promptCopyMsg = 'Prompt copied';
			setTimeout(() => (promptCopyMsg = null), 1800);
		} catch {
			promptCopyMsg = 'Copy failed';
		}
	}

	async function renderSeverityChart(
		mode: 'pie' | 'bar',
		counts: typeof severityCounts,
		canvas: HTMLCanvasElement | null,
		visible: boolean
	) {
		if (!browser || !canvas || !visible) {
			severityChart?.destroy();
			severityChart = null;
			return;
		}
		if (!chartLib) {
			chartLib = await import('chart.js');
			chartLib.Chart.register(...chartLib.registerables);
		}
		const labels = ['critical', 'high', 'medium', 'low', 'info'];
		const data = labels.map((k) => counts[k as keyof typeof counts]);
		const key = `${mode}|${data.join(',')}`;
		if (lastChartKey === key && severityChart) return;
		lastChartKey = key;

		if (severityChart && lastChartMode !== mode) {
			severityChart.destroy();
			severityChart = null;
		}

		if (!severityChart) {
			severityChart = new chartLib.Chart(canvas, {
				type: mode,
				data: {
					labels: labels.map((l) => l.toUpperCase()),
					datasets: [
						{
							label: 'Final severity distribution',
							data,
							backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6', '#64748b'],
							borderColor: '#0f172a',
							borderWidth: 1
						}
					]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					plugins: {
						legend: {
							position: 'bottom',
							labels: { color: '#cbd5e1', boxWidth: 12, boxHeight: 12 }
						}
					},
					scales:
						mode === 'bar'
							? {
									x: { ticks: { color: '#cbd5e1' }, grid: { color: 'rgba(148, 163, 184, 0.2)' } },
									y: {
										beginAtZero: true,
										ticks: { color: '#cbd5e1', precision: 0 },
										grid: { color: 'rgba(148, 163, 184, 0.2)' }
									}
								}
							: undefined
				}
			});
			lastChartMode = mode;
			return;
		}

		if (severityChart.data.datasets[0]) {
			severityChart.data.datasets[0].data = data;
		}
		severityChart.options = {
			...(severityChart.options ?? {}),
			scales:
				mode === 'bar'
					? {
							x: { ticks: { color: '#cbd5e1' }, grid: { color: 'rgba(148, 163, 184, 0.2)' } },
							y: { beginAtZero: true, ticks: { color: '#cbd5e1', precision: 0 }, grid: { color: 'rgba(148, 163, 184, 0.2)' } }
						}
					: undefined
		};
		severityChart.update();
		lastChartMode = mode;
	}

	$effect(() => {
		const mode = chartMode;
		const counts = severityCounts;
		const canvas = chartCanvas;
		const visible = showChart;
		void renderSeverityChart(mode, counts, canvas, visible);
	});

	$effect(() => {
		if (phaseBState !== 'running' && phaseBState !== 'done' && phaseDState !== 'running' && phaseDState !== 'done') {
			chartMode = 'pie';
		}
	});

	onDestroy(() => {
		severityChart?.destroy();
		severityChart = null;
		lastChartKey = '';
		lastChartMode = null;
	});
</script>

<svelte:head><title>New Scan</title></svelte:head>

<div class="page split">
	<section class="panel left">
		<h1>New Scan</h1>
		<p class="lede">Mount a directory first, then run each phase from its own box.</p>
		<form class="form" onsubmit={mountDirectory}>
			<label for="path">Absolute path to project root</label>
			<input
				id="path"
				name="sourcePath"
				type="text"
				autocomplete="off"
				placeholder="/home/you/projects/my-app"
				bind:value={sourcePath}
				disabled={mountLoading || mounted}
				class:locked={mounted}
			/>
			<div class="actions">
				<button
					type="submit"
					class="mount-btn tip-target"
					data-tooltip="Locks this directory path in place and initializes a new scan workspace."
					disabled={mountLoading || mounted || !sourcePath.trim()}
				>
					{mountLoading ? 'Mounting...' : mounted ? 'Mounted' : 'Mount directory'}
				</button>
			</div>
			{#if err}<p class="error" role="alert">{err}</p>{/if}
		</form>
		{#if scanId}
			<p class="muted mono">Scan ID: {scanId.slice(0, 8)}…</p>
		{/if}
	</section>

	<section class="panel right" class:show={mounted}>
		{#if !mounted}
			<p class="muted">Workspace appears here after mounting a directory.</p>
		{:else}
			<div class="grid3">
				<section class="phase-box">
					<h2>Light Scan</h2>
					<p class="phase-help">Fast, high-confidence static analysis rules.</p>
					<button
						class={`${phaseClass(phaseAState)} tip-target`}
						data-tooltip="Runs fast, high-confidence static analysis rules on source code."
						onclick={runPhaseA}
						disabled={phaseAState === 'running' || phaseAState === 'done'}
					>
						{#if phaseAState === 'running'}<span class="spinner" aria-hidden="true"></span>{/if}
						{phaseAButtonLabel}
					</button>
					<div class="progress"><div class={`bar ${phaseABarClass}`}></div></div>
					<p class="muted">Findings: {phaseA.length}</p>
				</section>

				<section class="phase-box">
					<h2>Deep Scan</h2>
					<p class="phase-help">Broader rules — diff against Light removes false positives.</p>
					<button
						class={`${phaseClass(phaseBState)} tip-target`}
						data-tooltip="Runs broader static analysis. Only findings confirmed by both Light and Deep survive to the final list."
						onclick={runPhaseB}
						disabled={phaseBState === 'running' || phaseBState === 'done' || (!scan?.assessmentFinishedAt && viewMode !== 'b-only')}
					>
						{#if phaseBState === 'running'}<span class="spinner" aria-hidden="true"></span>{/if}
						{phaseBButtonLabel}
					</button>
					<div class="progress"><div class={`bar ${phaseBBarClass}`}></div></div>
					<p class="muted">Findings: {phaseB.length}</p>
				</section>

				<section class="phase-box phase-box-dep">
					<h2>Dep Scan</h2>
					<p class="phase-help">Lockfile scan for known CVEs via OSV.dev.</p>
					<button
						class={`${phaseClass(phaseDState)} tip-target`}
						data-tooltip="Queries OSV.dev for known CVEs in your locked dependencies. Results go directly to the final list."
						onclick={runDepScanPhase}
						disabled={phaseDState === 'running' || phaseDState === 'done'}
					>
						{#if phaseDState === 'running'}<span class="spinner" aria-hidden="true"></span>{/if}
						{phaseDButtonLabel}
					</button>
					<div class="progress"><div class={`bar ${phaseDBarClass}`}></div></div>
					<p class="muted">Findings: {phaseD.length}</p>
				</section>
			</div>
			<div class="view-mode-wrap">
				<div class="view-mode-toggle" role="radiogroup" aria-label="Results view mode">
					<button type="button" class={`mode-opt ${viewMode === 'combined' ? 'active' : ''}`} onclick={() => (viewMode = 'combined')}>Combined</button>
					<button type="button" class={`mode-opt ${viewMode === 'a-only' ? 'active' : ''}`} onclick={() => (viewMode = 'a-only')}>Light only</button>
					<button type="button" class={`mode-opt ${viewMode === 'b-only' ? 'active' : ''}`} onclick={() => (viewMode = 'b-only')}>Deep only</button>
				</div>
			</div>
			<div class="run-all-wrap">
				<button
					class="run-all-btn tip-target"
					data-tooltip="Runs Light Scan, Deep Scan, and Dep Scan sequentially."
					onclick={runAllPhases}
					disabled={runAllLoading || phaseAState === 'running' || phaseBState === 'running' || phaseDState === 'running' || (phaseBState === 'done' && phaseDState === 'done')}
				>
					{#if runAllLoading}<span class="spinner" aria-hidden="true"></span>{/if}
					{runAllLoading ? 'Running all phases...' : 'Run All Phases'}
				</button>
			</div>

		{/if}
	</section>
</div>

{#if mounted}
	<section class="page fullstream">
		{#if showHydratedReport}
			<div class="new-scan-actions top">
				<button class="new-scan-btn tip-target" data-tooltip="Resets this workspace so you can run a new scan." onclick={startNewScan}>
					New Scan
				</button>
			</div>
		{/if}

		<section class="panel terminal fullwidth">
			<h2>Live scan output {#if logPhase === 'B'}(Deep Scan){:else if logPhase === 'D'}(Dep Scan){/if}</h2>
			<div class="term-box" role="log" aria-live="polite" aria-atomic="false">
				{#if logs.length === 0}
					<div class="line muted">No output yet.</div>
				{:else}
					{#each logs as l, i (`${i}-${l}`)}
						<div class="line">{l}</div>
					{/each}
				{/if}
			</div>
		</section>

		<section class="result-row" class:single-phase-a={showPhaseAResults && !showChart}>
			{#if showPhaseAResults && !showChart}
				{#if activeMode !== 'B'}
					<section class="panel mini result-card">
						<h3>Light Scan Results ({phaseA.length})</h3>
						<div class="mini-list">
							{#each phaseASummary as s (s.key)}
								<details class="finding-row">
									<summary class="item"><span class={`sev sev-${s.severity.toLowerCase()}`}>{s.severity}</span><span>{s.title} [{s.count}]</span></summary>
									<ul class="loc-list">
										{#each s.locations as loc (`${loc.label}`)}
											<li>{loc.label} [{loc.count}]</li>
										{/each}
									</ul>
								</details>
							{/each}
						</div>
					</section>
				{/if}
			{/if}

			{#if showPhaseDResults && activeMode === 'combined'}
				<section class="panel mini result-card">
					<h3>Dep Scan Results ({phaseD.length})</h3>
					<div class="mini-list">
						{#each phaseDSummary as s (s.key)}
							<details class="finding-row">
								<summary class="item"><span class={`sev sev-${s.severity.toLowerCase()}`}>{s.severity}</span><span>{s.title} [{s.count}]</span></summary>
								<ul class="loc-list">
									{#each s.locations as loc (`${loc.label}`)}
										<li>{loc.label} [{loc.count}]</li>
									{/each}
								</ul>
							</details>
						{/each}
					</div>
				</section>
			{/if}

			{#if showChart}
				<section class="panel mini chart-panel result-card">
					<div class="chart-toggle" role="group" aria-label="Severity chart mode toggle">
						<button
							type="button"
							class={`toggle-opt ${chartMode === 'pie' ? 'active' : ''}`}
							onclick={() => (chartMode = 'pie')}
						>
							Pie
						</button>
						<button
							type="button"
							class={`toggle-opt ${chartMode === 'bar' ? 'active' : ''}`}
							onclick={() => (chartMode = 'bar')}
						>
							Bar
						</button>
					</div>
					<div class="chart-wrap"><canvas bind:this={chartCanvas} aria-label="Final severity distribution chart"></canvas></div>
					<div class="legend-row">
						<span class="legend-item sev sev-critical">critical</span>
						<span class="legend-item sev sev-high">high</span>
						<span class="legend-item sev sev-medium">medium</span>
						<span class="legend-item sev sev-low">low</span>
						<span class="legend-item sev sev-info">info</span>
					</div>
				</section>

				<section class="panel mini result-card">
					<h3>Light Scan Results ({phaseA.length})</h3>
					<div class="mini-list">
						{#each phaseASummary as s (s.key)}
							<details class="finding-row">
								<summary class="item"><span class={`sev sev-${s.severity.toLowerCase()}`}>{s.severity}</span><span>{s.title} [{s.count}]</span></summary>
								<ul class="loc-list">
									{#each s.locations as loc (`${loc.label}`)}
										<li>{loc.label} [{loc.count}]</li>
									{/each}
								</ul>
							</details>
						{/each}
					</div>
				</section>

				{#if activeMode !== 'A'}
					<section class="panel mini result-card">
						<h3>Deep Scan Results ({phaseB.length})</h3>
						<div class="mini-list">
							{#each phaseBSummary as s (s.key)}
								<details class="finding-row">
									<summary class="item"><span class={`sev sev-${s.severity.toLowerCase()}`}>{s.severity}</span><span>{s.title} [{s.count}]</span></summary>
									<ul class="loc-list">
										{#each s.locations as loc (`${loc.label}`)}
											<li>{loc.label} [{loc.count}]</li>
										{/each}
									</ul>
								</details>
							{/each}
						</div>
					</section>
				{/if}

				<section class="panel mini result-card">
					<h3>Differences</h3>
					{#if falsePositives.length === 0 && missedByA.length === 0}
						<p class="muted">No differences between Light and Deep scans</p>
					{:else}
						<p class="muted">Light-only (filtered out): {falsePositives.length}</p>
						<p class="muted">Deep-only (added): {missedByA.length}</p>
					{/if}
				</section>
			{/if}
		</section>

		{#if showFinal}
			<section class="panel mini final-panel result-card">
				<h3>FINAL ({finalFindings.length})</h3>
				<div class="mini-list">
					{#each finalSummary as s (s.key)}
						<details class="finding-row">
							<summary class="item pick" onclick={() => (selectedFinal = s.firstId)}><span class={`sev sev-${s.severity.toLowerCase()}`}>{s.severity}</span><span>{s.title} [{s.count}]</span></summary>
							<ul class="loc-list">
								{#each s.locations as loc (`${loc.label}`)}
									<li>{loc.label} [{loc.count}]</li>
								{/each}
							</ul>
						</details>
					{/each}
				</div>
			</section>
		{/if}

		<section class="panel detail hydrated" class:show={showHydratedReport}>
			<h3>Final Detail</h3>
			{#if !selected}
				<p class="muted">No final findings yet.</p>
			{:else}
				<p class="muted mono">{selected.filePath}{selected.line != null ? `:${selected.line}` : ''}</p>
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
							<button class="btn small" onclick={copyReferences}>Copy references</button>
							<button
								class="btn small"
								onclick={() => {
									if (!confirm(`Open ${selectedReferences.length} references in new tabs?`)) return;
									for (const ref of selectedReferences) window.open(ref.url, '_blank', 'noopener,noreferrer');
								}}
							>
								Open all
							</button>
							{#if copyMsg}<span class="muted">{copyMsg}</span>{/if}
						</div>
					</div>
					<ul class="refs">
						{#each selectedReferences as ref (`${ref.url}`)}
							<li><a href={ref.url} target="_blank" rel="noreferrer">{ref.label}</a>{#if ref.reason}<span class="ref-reason"> - {ref.reason}</span>{/if}</li>
						{/each}
					</ul>
				{/if}
				<div class="prompt-head">
					<strong>Copy-ready AI prompt</strong>
					<div class="prompt-actions">
						<button class="btn small" onclick={() => copyPrompt(selected.fixPrompt)}>Copy</button>
						{#if promptCopyMsg}<span class="muted">{promptCopyMsg}</span>{/if}
					</div>
				</div>
				<pre class="snippet">{selected.fixPrompt}</pre>
			{/if}
		</section>

		{#if showHydratedReport}
			<div class="new-scan-actions bottom">
				<button class="new-scan-btn tip-target" data-tooltip="Resets this workspace so you can run another scan." onclick={startNewScan}>
					New Scan
				</button>
			</div>
		{/if}
	</section>
{/if}

<style>
	.page { max-width: 94rem; margin: 0 auto; padding: 1.4rem 1rem 2.2rem; }
	.split { display: grid; grid-template-columns: 1fr; gap: 1rem; }
	@media (min-width: 1100px) { .split { grid-template-columns: 0.88fr 1.12fr; } }
	.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem 1.1rem; }
	h1 { margin: 0 0 0.55rem; font-size: 1.65rem; }
	.lede { color: var(--muted); margin: 0 0 0.9rem; }
	.form label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.35rem; }
	.form input { width: 100%; padding: 0.56rem 0.64rem; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); color: var(--text); }
	.form input.locked { background: #374151; color: #9ca3af; border-color: #4b5563; }
	.actions { margin-top: 0.75rem; }
	.mount-btn { background: #2563eb; color: #fff; border: none; padding: 0.5rem 0.95rem; border-radius: 6px; font-weight: 700; cursor: pointer; }
	.mount-btn:disabled { opacity: 0.65; cursor: not-allowed; }
	.error { color: #f87171; margin-top: 0.6rem; font-size: 0.9rem; }
	.muted { color: var(--muted); }
	.mono { font-family: ui-monospace, monospace; }
	.right { opacity: 0.35; transform: translateY(8px); transition: opacity 0.32s ease, transform 0.32s ease; }
	.right.show { opacity: 1; transform: translateY(0); }
	.grid2 { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
	@media (min-width: 720px) { .grid2 { grid-template-columns: 1fr 1fr; } }
	.grid3 { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
	@media (min-width: 720px) { .grid3 { grid-template-columns: 1fr 1fr; } }
	@media (min-width: 1100px) { .grid3 { grid-template-columns: 1fr 1fr 1fr; } }
	.phase-box-dep { border-color: #1d4ed8; }
	.phase-box { background: var(--bg); border: 1px solid var(--border); border-radius: 10px; padding: 0.75rem; }
	.phase-box h2 { margin: 0 0 0.55rem; font-size: 0.95rem; }
	.phase-help { margin: -0.2rem 0 0.55rem; font-size: 0.78rem; color: var(--muted); }
	.view-mode-wrap { margin-top: 0.7rem; display: flex; justify-content: center; }
	.view-mode-toggle { display: inline-flex; border: 1px solid var(--border); border-radius: 999px; overflow: hidden; background: var(--bg); }
	.mode-opt { border: none; background: transparent; color: var(--muted); font-size: 0.77rem; padding: 0.28rem 0.72rem; cursor: pointer; }
	.mode-opt.active { background: #2563eb; color: #fff; font-weight: 700; }
	.phase-btn { width: 100%; border: none; border-radius: 8px; padding: 0.52rem 0.74rem; font-weight: 800; cursor: pointer; }
	.phase-btn.ready { background: #dc2626; color: #fff; }
	.phase-btn.running { background: #4b5563; color: #e5e7eb; }
	.phase-btn.done { background: #16a34a; color: #fff; }
	.phase-btn:disabled { cursor: not-allowed; }
	.spinner { width: 0.85rem; height: 0.85rem; border-radius: 999px; border: 2px solid rgba(255, 255, 255, 0.35); border-top-color: #fff; display: inline-block; margin-right: 0.35rem; vertical-align: -0.12rem; animation: spin 0.9s linear infinite; }
	.run-all-wrap { margin-top: 0.75rem; display: flex; justify-content: center; }
	.run-all-btn { border: 1px solid #1d4ed8; background: #2563eb; color: #f8fafc; border-radius: 8px; padding: 0.5rem 1rem; font-weight: 700; cursor: pointer; min-width: 13rem; }
	.run-all-btn:disabled { opacity: 0.65; cursor: not-allowed; }
	.progress { margin-top: 0.55rem; height: 8px; border-radius: 999px; background: #1f2937; overflow: hidden; border: 1px solid #334155; }
	.bar { height: 100%; background: linear-gradient(90deg, #3b82f6, #22c55e); transition: width 0.35s ease; }
	.bar-0 { width: 0%; }
	.bar-60 { width: 60%; }
	.bar-100 { width: 100%; }
	.fullstream { padding-top: 0; }
	.fullwidth { width: 100%; margin-top: 0.2rem; }
	.terminal { margin-top: 0.9rem; }
	.terminal h2 { margin: 0 0 0.55rem; font-size: 0.95rem; }
	.term-box { max-height: 15.5rem; overflow: auto; background: #0a0c10; border: 1px solid var(--border); border-radius: 8px; padding: 0.58rem 0.68rem; font-family: ui-monospace, monospace; font-size: 0.78rem; line-height: 1.45; }
	.line { white-space: pre-wrap; }
	.result-row { display: flex; flex-wrap: wrap; align-items: stretch; justify-content: center; gap: 0.9rem; margin-top: 1.1rem; }
	.result-row.single-phase-a { justify-content: flex-start; }
	.hydrated { opacity: 0; max-height: 0; overflow: hidden; transform: translateY(10px); transition: opacity 0.35s ease, transform 0.35s ease, max-height 0.35s ease; }
	.hydrated.show { opacity: 1; max-height: 2500px; transform: translateY(0); margin-top: 0.9rem; }
	.mini { padding: 0.75rem; flex: 0 1 22rem; width: 22rem; max-width: 100%; min-width: 16rem; }
	.result-card { animation: fade-in-up 0.22s ease; }
	.mini h3 { margin: 0 0 0.45rem; font-size: 0.9rem; }
	.mini-list { max-height: 12rem; overflow: auto; display: grid; gap: 0.3rem; }
	.item { display: grid; grid-template-columns: auto 1fr; gap: 0.45rem; align-items: center; font-size: 0.8rem; text-align: left; }
	.pick { background: transparent; border: 1px solid transparent; border-radius: 6px; padding: 0.22rem; }
	.pick:hover { border-color: var(--border); }
	.sev { font-size: 0.65rem; text-transform: uppercase; border-radius: 4px; padding: 0.1rem 0.32rem; background: #334155; color: #cbd5e1; }
	.sev-high, .sev-critical { background: rgba(220, 38, 38, 0.24); color: #fca5a5; border: 1px solid rgba(248, 113, 113, 0.36); }
	.sev-medium { background: rgba(245, 158, 11, 0.24); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.35); }
	.sev-low, .sev-info { background: rgba(59, 130, 246, 0.2); color: #bfdbfe; border: 1px solid rgba(96, 165, 250, 0.34); }
	.final-panel { border-color: #3b82f6; background: var(--surface); margin: 1.2rem auto 0; text-align: left; width: min(46rem, 100%); }
	.final-panel h3 { margin: 0 0 0.45rem; color: var(--text); }
	.final-panel .item { color: var(--text); }
	.chart-panel { display: flex; flex-direction: column; justify-content: space-between; }
	.chart-toggle { margin-top: 0.1rem; display: inline-flex; align-self: center; border: 1px solid var(--border); border-radius: 999px; overflow: hidden; background: var(--bg); }
	.toggle-opt { border: none; background: transparent; color: var(--muted); padding: 0.24rem 0.7rem; font-size: 0.78rem; cursor: pointer; }
	.toggle-opt.active { background: #2563eb; color: #fff; font-weight: 700; }
	.chart-wrap { margin: 0.45rem auto 0; height: 170px; width: min(20rem, 100%); }
	.chart-wrap canvas { width: 100% !important; height: 100% !important; }
	.legend-row { margin-top: 0.5rem; display: flex; justify-content: center; flex-wrap: wrap; gap: 0.35rem; }
	.legend-item { font-size: 0.62rem; }
	.detail { margin-top: 1.2rem; }
	.detail h3 { margin: 0 0 0.45rem; }
	.refs-head { display: flex; justify-content: space-between; gap: 0.6rem; align-items: center; flex-wrap: wrap; margin-top: 0.5rem; }
	.refs-head p { margin: 0; }
	.refs-actions { display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; }
	.refs-mode { background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 0.24rem 0.4rem; font-size: 0.8rem; }
	.btn { background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 0.28rem 0.5rem; cursor: pointer; }
	.btn.small { font-size: 0.75rem; }
	.refs { margin: 0.55rem 0 0.2rem; padding-left: 1rem; }
	.refs li { margin: 0.2rem 0; color: var(--muted); }
	.ref-reason { color: var(--muted); }
	.prompt-head { margin-top: 0.6rem; display: flex; justify-content: space-between; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
	.prompt-actions { display: inline-flex; align-items: center; gap: 0.45rem; }
	.snippet { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.58rem; font-size: 0.8rem; white-space: pre-wrap; overflow: auto; }
	.finding-row { border: 1px solid transparent; border-radius: 6px; padding: 0.15rem 0.2rem; }
	.finding-row[open] { border-color: var(--border); background: rgba(30, 41, 59, 0.22); }
	.finding-row summary { cursor: pointer; list-style: none; }
	.finding-row summary::-webkit-details-marker { display: none; }
	.loc-list { margin: 0.35rem 0 0.2rem 1.35rem; padding: 0; font-size: 0.74rem; color: var(--muted); display: grid; gap: 0.15rem; }
	.new-scan-actions { display: flex; justify-content: center; }
	.new-scan-actions.top { margin-bottom: 0.75rem; }
	.new-scan-actions.bottom { margin-top: 1rem; }
	.new-scan-btn { border: 1px solid #1d4ed8; background: #2563eb; color: #fff; border-radius: 8px; padding: 0.5rem 1rem; font-weight: 700; cursor: pointer; }
	.new-scan-btn:hover { background: #1d4ed8; }
	@keyframes fade-in-up {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: translateY(0); }
	}
	@keyframes spin {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}
</style>
