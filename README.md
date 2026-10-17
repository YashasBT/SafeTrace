# SafeTrace

## Frontend upgrade
The Streamlit interface now includes a polished dark privacy console, guided workspace navigation, scan activity, file import, side-by-side log input/output, richer scan reports, privacy experiment visualization, benchmark charts and JSON export, and an opt-in AI diagnosis workflow. External Google Fonts are optional visual enhancement; the app remains usable without them.

**Existing tools hide secrets. SafeTrace measures whether what's left is still useful.**

Local-first Streamlit MVP for detecting common sensitive values in logs, replacing them with stable pseudonyms, and comparing privacy/diagnostic utility.

## Features
- Regex/context and entropy-based local detection.
- Consistent session-scoped pseudonyms.
- Stack trace context preservation.
- Synthetic canary privacy lab.
- Raw vs naive redaction vs SafeTrace benchmark.
- Optional opt-in Ollama diagnosis, with sanitized text only.
- Pytest suite and methodology documentation.

**Benchmark caveat:** the five included cases are synthetic, not public issue traces. The diagnostic metric is heuristic term overlap, not validated diagnosis accuracy.

## Install
Python 3.11+ recommended.

Windows PowerShell:
```powershell
py -3.11 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run
```bash
streamlit run app.py
```
## Tests and benchmark
```bash
python -m pytest -q
python scripts/generate_demo_data.py
python scripts/run_benchmark.py
```
Benchmark results are computed and written to `benchmark_report.json`.

## Optional Ollama
Install Ollama, run `ollama pull llama3.2`, then use the AI Diagnosis panel and explicitly check consent. Only sanitized text entered into that panel is sent to the configured endpoint. Do not use an untrusted endpoint.

## Formulas
Leak rate = complete canary values surviving / total injected canaries × 100. Privacy score = 100 − leak rate. Diagnostic score = fraction of expected reference terms present. Neither metric guarantees security or correct diagnosis.

## Provenance and limitations
See `data/DATASET_SOURCES.md`, `docs/evaluation_methodology.md`, and `docs/limitations.md`. The included cases are synthetic. Add licensed public examples with source URLs, documented fixes, and human-reviewed rubrics before making real-world performance claims. Always inspect sanitized output before sharing.


## SafeTrace Ultra
The UI removes the Ollama AI diagnosis page and adds an ML Intelligence workbench, premium dark dashboard, candidate reports, privacy lab charts, benchmark visualization, and CSV/JSON exports. The ML detector is advisory and does not replace the primary sanitizer.
