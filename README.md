# KitScan

KitScan is a local, web-based security scanning tool for source code projects.

Explainable by design. Findings are shown with severity, file location, remediation guidance, and references you can use to validate the result.

## What it does

KitScan uses a two-phase scan flow:

1. **Phase A**: fast baseline scan to surface likely security issues.
2. **Phase B**: deeper source scan to validate/refine findings and reduce noise.

After scanning, the UI shows:

- grouped findings with counts (and expandable locations)
- a severity chart (pie/bar toggle)
- differences between phases (in combined mode)
- a final actionable list
- a copy-ready AI remediation prompt for each selected finding

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

1. Open the UI.
2. Mount a project directory.
3. Run **Phase A** (or use **Run All Phases**).
4. Run **Phase B** for deeper analysis.
5. Review grouped findings and expand rows for exact file locations.
6. References provided based on results, if needed

## Notes on accuracy

KitScan uses deterministic static analysis rules and heuristics. It is meant for fast scanning and fixes, but it is not a complete replacement for manual review, runtime testing, or a full penetration test.

Use it as a practical security tool, not a final security guarantee.
