from .dataset import load_cases
from .sanitizer import sanitize
from .diagnosis import score_diagnosis
def naive_redact(text):
    from .detector import detect
    for f in reversed(detect(text)): text=text[:f.start]+"[REDACTED]"+text[f.end:]
    return text
def run_benchmark(path):
    cases=load_cases(path); names=["Raw logs","Naive redaction","SafeTrace"]
    scores={n:[] for n in names}; privacy={n:[] for n in names}
    for c in cases:
        raw=c["original_trace"]
        variants={"Raw logs":raw,"Naive redaction":naive_redact(raw),"SafeTrace":sanitize(raw).sanitized_text}
        for name,txt in variants.items():
            scores[name].append(score_diagnosis(txt,c))
            cs=c.get("canaries",[])
            if cs: privacy[name].append(0.0 if any(x in txt for x in cs) else 100.0)
    return {"sample_size":len(cases),"evaluation_type":"automated heuristic; not human-verified diagnosis","methods":{
      n:{"diagnosis_accuracy":round(sum(scores[n])/len(scores[n])*100,2) if scores[n] else 0.0,
         "mean_diagnostic_score":round(sum(scores[n])/len(scores[n]),4) if scores[n] else 0.0,
         "privacy_score":round(sum(privacy[n])/len(privacy[n]),2) if privacy[n] else None} for n in names}}
