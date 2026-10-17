import re, requests
def score_diagnosis(text, case):
    terms=[x for x in re.findall(r"[a-z0-9_]+",case["expected_root_cause"].lower()) if len(x)>3]
    terms+= [str(x).lower() for x in case["diagnostic_keywords"]]
    terms=list(dict.fromkeys(terms))
    return sum(t in text.lower() for t in terms)/len(terms) if terms else 0.0
def diagnose_with_ollama(sanitized_text, model="llama3.2", base_url="http://localhost:11434", timeout=30):
    r=requests.post(base_url.rstrip("/")+"/api/generate",json={"model":model,"prompt":"Diagnose this sanitized log. State likely cause, evidence, and next steps.\n\n"+sanitized_text,"stream":False},timeout=timeout)
    r.raise_for_status()
    return str(r.json().get("response","No response returned."))
