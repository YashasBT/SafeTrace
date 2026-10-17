import inspect
from safetrace.diagnosis import diagnose_with_ollama
def test_argument_name():
    assert list(inspect.signature(diagnose_with_ollama).parameters)[0]=="sanitized_text"
