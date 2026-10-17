import json, pytest
from safetrace.benchmark import run_benchmark,naive_redact
from safetrace.dataset import load_cases
def test_benchmark():
    r=run_benchmark("data/benchmark_cases.json")
    assert r["sample_size"]==5 and len(r["methods"])==3
def test_naive():
    assert "[REDACTED]" in naive_redact("email a@example.com")
def test_bad_data(tmp_path):
    p=tmp_path/"bad.json"; p.write_text(json.dumps([{"case_id":"x"}]),encoding="utf-8")
    with pytest.raises(ValueError): load_cases(p)
