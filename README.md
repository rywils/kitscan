# KitScan

KitScan is a local, web-based security scanner for source code projects.

Explainable by design. Findings are shown with severity, file location, remediation guidance, and references you can use to validate the result.

## What it does

KitScan combines static analysis with dependency vulnerability scanning:

- **Phase A**: fast baseline scan — static analysis rules plus dependency vulnerability lookup via [OSV.dev](https://osv.dev/).
- **Phase B**: deeper source scan to validate/refine findings and reduce noise.

After scanning, the UI shows:

- grouped findings with counts (and expandable file locations)
- a severity chart (pie/bar toggle)
- a **Combined / Phase A only / Phase B only** view mode toggle
- a final actionable list
- a copy-ready AI remediation prompt for each selected finding
- references to OWASP, CWE, NVD, and other resources per finding

## Prerequisites

- Node.js 20+
- npm

## How to install

From the project root:

```bash
./install
```

This installs dependencies and builds the production app.

## How to run

From the project root:

```bash
./kitscan
```

You will see:

`Your Web UI is accessible at: http://localhost:<port>`

Open that URL in your browser.

### Useful flags

```bash
./kitscan --help
./kitscan -p 3001
./kitscan --port 8080
```

## Typical usage flow

1. Open the UI and go to **New Scan**.
2. Enter the **absolute path** to your project root and click **Mount directory**.
3. Run **Phase A** (or click **Run All Phases** to run both sequentially).
4. Run **Phase B** for deeper analysis.
5. Use the view mode toggle to see **Combined**, **Phase A only**, or **Phase B only** results.
6. Review grouped findings and expand rows for exact file locations.
7. Copy the AI remediation prompt for any finding to get targeted fix suggestions.

## Notes on accuracy

KitScan uses deterministic static analysis rules, heuristics, and a live CVE database lookup. It is meant for fast scanning and fixes, but it is not a complete replacement for manual review, runtime testing, or a full penetration test.

Use it as a practical security tool, not a final security guarantee.
