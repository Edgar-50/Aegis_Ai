from pathlib import Path
import yaml
from app.models.schemas import SecurityEventIn

RULE_FILE = Path(__file__).resolve().parents[2] / "rules" / "sigma_rules.yml"


class SigmaEngine:
    def __init__(self):
        self.rules = []
        self.reload()

    def reload(self):
        try:
            self.rules = yaml.safe_load(RULE_FILE.read_text()).get("rules", [])
        except Exception:
            self.rules = []

    def match(self, event: SecurityEventIn) -> list[dict]:
        hits = []
        for rule in self.rules:
            ok = True
            if value := rule.get("event_type_contains"):
                ok &= value.lower() in event.event_type.lower()
            if value := rule.get("process_contains"):
                ok &= value.lower() in (event.process_name or "").lower()
            if value := rule.get("failed_attempts_gte"):
                ok &= event.failed_attempts >= int(value)
            if ok:
                hits.append(rule)
        return hits


SIGMA = SigmaEngine()
