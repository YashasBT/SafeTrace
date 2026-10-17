import json, sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from safetrace.benchmark import run_benchmark
result=run_benchmark(str(root/"data"/"benchmark_cases.json"))
out=root/"benchmark_report.json"
out.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result, indent=2))
print(f"\\nReport written to: {out}")
