import json
REQUIRED={"case_id","original_trace","expected_root_cause","diagnostic_keywords","verified_fix","source_url","license_notes","provenance"}
def load_cases(path):
    with open(path,encoding="utf-8") as f: data=json.load(f)
    if not isinstance(data,list): raise ValueError("Benchmark dataset must be a JSON list.")
    for i,c in enumerate(data):
        if not isinstance(c,dict): raise ValueError(f"Case {i} must be an object.")
        missing=REQUIRED-set(c)
        if missing: raise ValueError(f"Case {i} missing fields: {', '.join(sorted(missing))}")
        if not isinstance(c["diagnostic_keywords"],list): raise ValueError(f"Case {i} diagnostic_keywords must be a list.")
    return data
