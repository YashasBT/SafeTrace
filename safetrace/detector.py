import math, re
from collections import Counter
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    value: str
    category: str
    priority: int = 10

def entropy(s):
    if not s: return 0.0
    n=len(s); counts=Counter(s)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

PATTERNS = [
 ("authorization", re.compile(r"(?i)(?<=Bearer )[A-Za-z0-9._~+/=-]{8,}"), 100),
 ("database_credential", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/@]+:[^@\s/]+@[^ \r\n]+"), 95),
 ("api_key", re.compile(r"\b(?:sk_live|sk_test|gh[pousr]_|AKIA|AIza|xox[baprs]-)[A-Za-z0-9_\-]{8,}\b"), 90),
 ("assignment_secret", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*([=:])\s*(['\"]?)([^'\"\s,;]+)\3"), 85),
 ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 40),
 ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 30),
 ("unix_username_path", re.compile(r"(?<=/home/)[A-Za-z_][A-Za-z0-9._-]{0,31}(?=/)"), 20),
]
def detect(text, entropy_min_length=24, entropy_threshold=4.0):
    out=[]
    for cat, pat, priority in PATTERNS:
        for m in pat.finditer(text):
            if cat == "assignment_secret":
                start,end=m.span(4); value=m.group(4)
            else:
                start,end=m.span(); value=m.group(0)
            if value: out.append(Finding(start,end,value,cat,priority))
    token=re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{%d,}(?![A-Za-z0-9])" % entropy_min_length)
    for m in token.finditer(text):
        val=m.group(0)
        if entropy(val)>=entropy_threshold and not any(f.start<m.end() and m.start()<f.end for f in out):
            out.append(Finding(m.start(),m.end(),val,"high_entropy",10))
    out.sort(key=lambda f:(f.start,-f.priority,-(f.end-f.start)))
    resolved=[]
    for f in out:
        if resolved and f.start < resolved[-1].end:
            if (f.priority,f.end-f.start)>(resolved[-1].priority,resolved[-1].end-resolved[-1].start):
                resolved[-1]=f
        else: resolved.append(f)
    return resolved
