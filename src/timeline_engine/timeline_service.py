from datetime import datetime

class TimelineService:
    def __init__(self):
        self.events = []

    def add(self, event_type, timestamp, source, details=""):
        self.events.append({"event_type": event_type, "timestamp": timestamp, "source": source, "details": details})
        self.events.sort(key=lambda e: e["timestamp"])

    def list(self, start=None, end=None):
        out = self.events
        if start: out = [e for e in out if e["timestamp"] >= start]
        if end: out = [e for e in out if e["timestamp"] <= end]
        return out
