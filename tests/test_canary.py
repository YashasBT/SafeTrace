import pytest
from safetrace.canary import generate_canaries,evaluate_canaries
def test_generate():
    c=generate_canaries(4); assert len(c)==4 and len({x["value"] for x in c})==4
def test_metrics():
    c=[{"category":"test","value":"ordinary_canary_value_123456"}]; r=evaluate_canaries(c)
    assert (r.total,r.detected,r.leaked,r.leak_rate,r.privacy_score)==(1,1,0,0,100)
def test_invalid_count():
    with pytest.raises(ValueError): generate_canaries(0)
