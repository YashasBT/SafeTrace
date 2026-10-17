from collections import defaultdict
class Pseudonymizer:
    def __init__(self):
        self._labels=defaultdict(dict); self._counts=defaultdict(int)
    def label(self, category, value):
        m=self._labels[category]
        if value not in m:
            self._counts[category]+=1; m[value]=f"{category.upper()}_{self._counts[category]}"
        return m[value]
    def clear(self):
        self._labels.clear(); self._counts.clear()
def display_category(category):
    return {"api_key":"API_KEY","assignment_secret":"SECRET","authorization":"TOKEN",
    "database_credential":"DATABASE_CREDENTIAL","email":"EMAIL","ipv4":"IP_ADDRESS",
    "unix_username_path":"USERNAME","high_entropy":"HIGH_ENTROPY_SECRET"}.get(category,category.upper())
