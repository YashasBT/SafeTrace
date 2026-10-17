from __future__ import annotations
import math, re
from dataclasses import dataclass

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
except Exception:
    TfidfVectorizer = LogisticRegression = Pipeline = None

CANDIDATE_RE = re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?[^,\s\"']{4,160}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b|\b[A-Za-z0-9_./+=-]{24,}\b")
CONTEXT = re.compile(r"(?i)(password|passwd|secret|api.?key|token|authorization|credential|private.?key|database.?url|dsn)")
PLACEHOLDER = re.compile(r"(?i)^\[?(?:REDACTED|TOKEN|SECRET|API_KEY|PASSWORD|EMAIL|IP_ADDRESS|USERNAME|CANARY)(?:[_ -]?\d+)?\]?$")

@dataclass
class Candidate:
    value: str
    start: int
    end: int
    label: str
    confidence: float
    reasons: list[str]

def _entropy(s):
    if not s: return 0.0
    from collections import Counter
    n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in Counter(s).values())

def _training():
    pos = [
        "password=supersecret123", "api_key=sk_live_8a9b7c6d5e4f3g2h",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "client_secret: x9Kp2Lm7Qa4Vt8Wz", "database_url=postgres://admin:Pass123@db.local:5432/app",
        "private_key=-----BEGIN_PRIVATE_KEY-----", "token=ghp_1234567890abcdefghijkl",
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "refresh_token=0a9d8c7b6e5f4g3h2i1j",
        "passwd: letmein12345", "credential=Qx9!rT2#vL8@kM5", "secret_key: abcdef1234567890ABCDEF"
    ]
    neg = [
        "HTTP 503 Service Unavailable", "ConnectionTimeoutError after 30 seconds",
        "File /app/services/database.py line 87", "retry_count=3", "request_id=abc-123",
        "user_id=1042", "status_code=401", "GET /api/v1/users returned 200",
        "NullPointerException at Worker.run", "database connection pool exhausted",
        "latency_ms=142", "attempt=2", "feature_flag=enable_cache", "region=ap-south-1"
    ]
    return pos, neg

def train_classifier():
    if Pipeline is None: return None
    pos, neg = _training()
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2,5), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=500, class_weight="balanced", random_state=17))
    ])
    model.fit(pos+neg, [1]*len(pos)+[0]*len(neg))
    return model

def detect_candidates(text: str, threshold: float=0.62) -> list[Candidate]:
    if not text: return []
    model=train_classifier()
    results=[]; seen=set()
    for m in CANDIDATE_RE.finditer(text):
        raw=m.group(0)
        value=raw.split("=",1)[-1].split(":",1)[-1].strip().strip("'\\\"") if re.search(r"(?i)(password|passwd|secret|api.?key|token|credential)\\s*[:=]",raw) else raw
        if not value or PLACEHOLDER.fullmatch(value): continue
        prefix=text[max(0,m.start()-80):m.start()]
        context=text[max(0,m.start()-80):min(len(text),m.end()+40)]
        reasons=[]
        if CONTEXT.search(prefix+" "+raw): reasons.append("sensitive-field context")
        if len(value)>=16 and _entropy(value)>=3.4: reasons.append("high character entropy")
        if raw.lower().startswith("bearer ") or raw.startswith("eyJ"): reasons.append("credential syntax")
        if not reasons: continue
        confidence=0.5
        if model is not None:
            try: confidence=float(model.predict_proba([context])[0][1])
            except Exception: pass
        if "credential syntax" in reasons: confidence=max(confidence,0.96)
        elif "sensitive-field context" in reasons: confidence=max(confidence,0.88)
        elif "high character entropy" in reasons: confidence=max(confidence,0.68)
        key=(m.start(),m.end())
        if confidence>=threshold and key not in seen:
            seen.add(key); results.append(Candidate(value,m.start(),m.end(),"SECRET_CANDIDATE",confidence,reasons))
    return results

def model_status():
    if Pipeline is None:
        return {"available":False,"name":"Hybrid heuristic fallback","note":"Install scikit-learn to enable the contextual classifier."}
    return {"available":True,"name":"TF-IDF character n-grams + Logistic Regression","note":"Prototype trained on a small synthetic dataset; scores are not calibrated probabilities."}
