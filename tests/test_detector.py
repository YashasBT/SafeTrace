from safetrace.detector import detect
def test_api_key_password():
    fs=detect("api_key=demoSecretValue123 password=hunter2")
    assert any(f.category=="assignment_secret" for f in fs)
def test_bearer():
    assert any(f.category=="authorization" for f in detect("Authorization: Bearer abcdefghijklmnop"))
def test_email_ip():
    assert {"email","ipv4"} <= {f.category for f in detect("alice@example.com 192.168.1.25")}
def test_context_secret():
    assert any(f.value=="local-demo-secret" for f in detect("client_secret='local-demo-secret'"))
def test_entropy():
    assert any(f.category=="high_entropy" for f in detect("unknown=AbCdEfGhIjKlMnOpQrStUvWxYz012345",24,3.5))
