from src.database.models import Evidence, init_db

class EvidenceService:
    def __init__(self, db_path="data/forensics.db"):
        self.Session = init_db(db_path)

    def list_evidence(self, case_id=None):
        with self.Session() as s:
            q = s.query(Evidence)
            if case_id:
                q = q.filter(Evidence.case_id == case_id)
            return q.order_by(Evidence.id.desc()).all()

    def add_evidence(self, case_id, device_type, brand="", model="", serial="", custodian=""):
        with self.Session() as s:
            e = Evidence(case_id=case_id, device_type=device_type, brand=brand, model=model, serial=serial, custodian=custodian)
            s.add(e); s.commit(); s.refresh(e); return e
