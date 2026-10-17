from dataclasses import dataclass
from .detector import detect
from .pseudonymizer import Pseudonymizer, display_category
@dataclass
class SanitizationResult:
    sanitized_text: str
    replacements: int
    categories: dict
def sanitize(text, pseudonymizer=None, max_chars=200000):
    if not isinstance(text,str): raise TypeError("Input must be text.")
    if len(text)>max_chars: raise ValueError(f"Input exceeds the {max_chars:,}-character safety limit.")
    p=pseudonymizer or Pseudonymizer(); findings=detect(text); output=text; counts={}
    for f in reversed(findings):
        label=p.label(display_category(f.category),f.value)
        output=output[:f.start]+f"[{label}]"+output[f.end:]
        counts[f.category]=counts.get(f.category,0)+1
    return SanitizationResult(output,len(findings),counts)
