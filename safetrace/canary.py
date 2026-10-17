import secrets, string
from dataclasses import dataclass
from .sanitizer import sanitize
@dataclass
class CanaryReport:
    total:int; detected:int; leaked:int; leak_rate:float; privacy_score:float; leaked_categories:list
def generate_canaries(count=8):
    if count<1 or count>100: raise ValueError("Canary count must be between 1 and 100.")
    alphabet=string.ascii_letters+string.digits
    return [{"category":"synthetic_token","value":"CANARY_"+''.join(secrets.choice(alphabet) for _ in range(28))} for _ in range(count)]
def evaluate_canaries(canaries, raw_text=None):
    if not canaries: raise ValueError("At least one canary is required.")
    raw=raw_text if raw_text is not None else "\n".join(c["value"] for c in canaries)
    sanitized=sanitize(raw).sanitized_text
    leaked=[c for c in canaries if c["value"] in sanitized]
    rate=len(leaked)/len(canaries)*100
    return CanaryReport(len(canaries),len(canaries)-len(leaked),len(leaked),rate,100-rate,sorted({c["category"] for c in leaked}))
