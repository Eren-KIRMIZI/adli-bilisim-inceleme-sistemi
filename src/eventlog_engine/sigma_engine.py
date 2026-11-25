"""Sigma YAML Rule Engine for Windows Event Log (EVTX) Threat Hunting & MITRE ATT&CK Scoring.

Compatible with Hayabusa/Chainsaw-style detection over EventLogService records.
Uses PyYAML when installed, with a pure-Python fallback YAML parser for offline portability.
"""

import os
import re
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


BUILTIN_SIGMA_RULES_YAML: List[str] = [
    """title: PowerShell Encoded Command Execution
id: sigma-win-001
level: high
status: stable
description: Base64 kodlu veya gizli pencereli PowerShell çalıştırılması tespit edildi.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  service: security
detection:
  selection_eid:
    EventID: 4688
  selection_cmd:
    details|contains:
      - "-enc"
      - "-encodedcommand"
      - "hidden"
  condition: selection_eid and selection_cmd
""",
    """title: Security Event Log Cleared (Anti-Forensics)
id: sigma-win-002
level: critical
status: stable
description: Windows Güvenlik olay günlüğü silindi (EventID 1102).
tags:
  - attack.defense_evasion
  - attack.t1070.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
""",
    """title: Suspicious Service Installation (Persistence)
id: sigma-win-003
level: medium
status: stable
description: Sistemde yeni bir Windows servisi kuruldu (EventID 7045).
tags:
  - attack.persistence
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
  condition: selection
""",
    """title: Volume Shadow Copy Deletion Attempt
id: sigma-win-004
level: critical
status: stable
description: Fidye yazılımı / iz silme amaçlı vssadmin gölge kopya silme komutu tespit edildi.
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: windows
  service: security
detection:
  selection:
    details|contains:
      - "vssadmin delete shadows"
      - "shadowcopy delete"
  condition: selection
""",
    """title: Brute Force Failed Logon Indicator
id: sigma-win-005
level: medium
status: stable
description: Başarısız oturum açma denemesi (EventID 4625) tespit edildi.
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
""",
    """title: Scheduled Task Creation or Credential Tooling
id: sigma-win-006
level: high
status: stable
description: Zamanlanmış görev oluşturma (4698) veya kimlik bilgisi döküm aracı izi tespit edildi.
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
  service: security
detection:
  selection_task:
    EventID: 4698
  selection_cred:
    details|contains:
      - "mimikatz"
      - "sekurlsa"
      - "rclone"
  condition: selection_task or selection_cred
""",
]

LEVEL_SCORES = {"critical": 95, "high": 80, "medium": 60, "low": 35, "informational": 15}


def _minimal_yaml_load(text: str) -> Dict[str, Any]:
    """Fallback Sigma YAML subset parser when PyYAML is unavailable."""
    if HAS_YAML:
        doc = yaml.safe_load(text)
        return doc if isinstance(doc, dict) else {}

    res: Dict[str, Any] = {}
    lines = text.splitlines()
    stack: List[tuple] = [(-1, res)]
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if stripped.startswith("- ") and isinstance(parent, list):
            val = stripped[2:].strip().strip('"').strip("'")
            parent.append(int(val) if val.isdigit() else val)
            continue
        if ":" in stripped and isinstance(parent, dict):
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()
            if not v:
                # peek next non-empty line to decide list vs dict
                nxt = ""
                for j in range(i, len(lines)):
                    if lines[j].strip() and not lines[j].strip().startswith("#"):
                        nxt = lines[j].strip()
                        break
                container: Any = [] if nxt.startswith("- ") else {}
                parent[k] = container
                stack.append((indent, container))
            else:
                v_clean = v.strip('"').strip("'")
                parent[k] = int(v_clean) if v_clean.isdigit() else v_clean
    return res


class SigmaRuleEngine:
    """Evaluates Sigma YAML rules against parsed EVTX event records."""

    def __init__(self, extra_rules_yaml: Optional[List[str]] = None):
        self.rules: List[Dict[str, Any]] = []
        for y in BUILTIN_SIGMA_RULES_YAML:
            self.add_yaml_rule(y)
        for y in (extra_rules_yaml or []):
            self.add_yaml_rule(y)

    def add_yaml_rule(self, yaml_text: str) -> None:
        doc = _minimal_yaml_load(yaml_text)
        if doc and "detection" in doc:
            self.rules.append(doc)

    def load_rules_directory(self, folder: str) -> int:
        if not os.path.isdir(folder):
            return 0
        count = 0
        for root, _, files in os.walk(folder):
            for fn in files:
                if fn.lower().endswith((".yml", ".yaml")):
                    try:
                        with open(os.path.join(root, fn), "r", encoding="utf-8", errors="replace") as f:
                            self.add_yaml_rule(f.read())
                        count += 1
                    except Exception:
                        continue
        return count

    def _match_field_spec(self, ev: Dict[str, Any], key_spec: str, expected: Any) -> bool:
        parts = key_spec.split("|")
        field = parts[0]
        mods = set(parts[1:])

        # Resolve field from top-level event, Sigma aliases, event_data, or combined searchable text
        if field in ev:
            val = ev.get(field)
        elif field.lower() == "eventid":
            val = ev.get("event_id")
        elif isinstance(ev.get("event_data"), dict) and field in ev["event_data"]:
            val = ev["event_data"].get(field)
        else:
            val = f"{ev.get('description', '')} {ev.get('details', '')} {ev.get('event_data', '')}"

        candidates = expected if isinstance(expected, list) else [expected]
        if val is None:
            return False

        # Numeric equality (e.g. EventID)
        val_str = str(val)
        val_low = val_str.lower()

        def single_match(c: Any) -> bool:
            if isinstance(c, int) and str(val).isdigit():
                return int(val) == c
            c_str = str(c)
            c_low = c_str.lower()
            if "re" in mods:
                return bool(re.search(c_str, val_str, re.IGNORECASE))
            if "startswith" in mods:
                return val_low.startswith(c_low)
            if "endswith" in mods:
                return val_low.endswith(c_low)
            if "contains" in mods:
                return c_low in val_low
            return val_low == c_low

        if "all" in mods:
            return all(single_match(c) for c in candidates)
        return any(single_match(c) for c in candidates)

    def _eval_selection(self, ev: Dict[str, Any], sel: Any) -> bool:
        if isinstance(sel, dict):
            return all(self._match_field_spec(ev, k, v) for k, v in sel.items())
        if isinstance(sel, list):
            return any(self._eval_selection(ev, item) for item in sel)
        return False

    def _eval_condition(self, ev: Dict[str, Any], detection: Dict[str, Any]) -> bool:
        cond = str(detection.get("condition", "")).strip()
        if not cond:
            return False

        # Tokenize simple boolean expression (and / or / not / parentheses / selection names)
        tokens = re.findall(r"\(|\)|and|or|not|[A-Za-z0-9_.*]+", cond)
        out_expr: List[str] = []
        for tok in tokens:
            low = tok.lower()
            if low in ("(", ")", "and", "or", "not"):
                out_expr.append(low)
            elif "*" in tok:
                prefix = tok.replace("*", "")
                matched = any(self._eval_selection(ev, v) for k, v in detection.items() if k.startswith(prefix))
                out_expr.append("True" if matched else "False")
            elif tok in detection:
                out_expr.append("True" if self._eval_selection(ev, detection[tok]) else "False")
            else:
                out_expr.append("False")

        try:
            return bool(eval(" ".join(out_expr), {"__builtins__": {}}, {}))
        except Exception:
            return False

    def scan_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all loaded Sigma rules against parsed EVTX event dicts."""
        hits: List[Dict[str, Any]] = []
        for ev in events:
            for rule in self.rules:
                det = rule.get("detection", {})
                if self._eval_condition(ev, det):
                    lvl = str(rule.get("level", "medium")).lower()
                    hits.append({
                        "rule_id": rule.get("id", "-"),
                        "title": rule.get("title", "Sigma Match"),
                        "level": lvl,
                        "score": LEVEL_SCORES.get(lvl, 50),
                        "tags": ", ".join(rule.get("tags", [])),
                        "description": rule.get("description", ""),
                        "record_id": ev.get("record_id"),
                        "event_id": ev.get("event_id"),
                        "timestamp": ev.get("timestamp"),
                        "details": ev.get("details", ""),
                    })
        return hits
