import pytest
from safetrace.sanitizer import sanitize
from safetrace.pseudonymizer import Pseudonymizer
def test_preserves_trace():
    out=sanitize('AuthenticationError: alice@example.com\nFile "/home/alice/app.py", line 42, in authenticate\nHTTP 401').sanitized_text
    assert "AuthenticationError" in out and "line 42" in out and "HTTP 401" in out and "alice@example.com" not in out
def test_repeat():
    out=sanitize("alice@example.com and alice@example.com",Pseudonymizer()).sanitized_text
    assert out.count("[EMAIL_1]")==2
def test_empty_unicode():
    assert sanitize("").sanitized_text==""
    assert "UnicodeError" in sanitize("UnicodeError: café ☕").sanitized_text
def test_limit():
    with pytest.raises(ValueError): sanitize("x"*20,max_chars=10)
def test_type():
    with pytest.raises(TypeError): sanitize(None)
