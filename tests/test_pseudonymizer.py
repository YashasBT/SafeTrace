from safetrace.pseudonymizer import Pseudonymizer
def test_stable_and_distinct():
    p=Pseudonymizer(); a=p.label("EMAIL","a@example.com")
    assert p.label("EMAIL","a@example.com")==a and p.label("EMAIL","b@example.com")!=a
def test_clear():
    p=Pseudonymizer(); p.label("TOKEN","x"); p.clear()
    assert p.label("TOKEN","x")=="TOKEN_1"
