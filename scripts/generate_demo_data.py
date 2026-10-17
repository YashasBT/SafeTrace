import json,secrets,string
from pathlib import Path
root=Path(__file__).resolve().parents[1]; alphabet=string.ascii_letters+string.digits
payload={"warning":"Synthetic test data only. Never use real credentials.","canaries":["CANARY_"+''.join(secrets.choice(alphabet) for _ in range(28)) for _ in range(5)]}
p=root/"data"/"generated_canaries.json"; p.write_text(json.dumps(payload,indent=2),encoding="utf-8")
print(f"Generated {len(payload['canaries'])} synthetic canaries at {p}")
