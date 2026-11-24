from sqlalchemy.orm import Session
from src.database.models import Case, init_db

class CaseService:
    def __init__(self, db_path="data/forensics.db"):
        self.Session = init_db(db_path)

    def list_cases(self):
        with self.Session() as s:
            return s.query(Case).order_by(Case.id.desc()).all()

    def create_case(self, case_number, title, investigator="", description=""):
        with self.Session() as s:
            c = Case(case_number=case_number, title=title, investigator=investigator, description=description)
            s.add(c)
            s.commit()
            s.refresh(c)
            return c
