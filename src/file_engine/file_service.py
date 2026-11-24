import os, hashlib, mimetypes
from src.integrity_engine.integrity_service import IntegrityService

class FileAnalysisService:
    @staticmethod
    def analyze(path):
        st = os.stat(path)
        return {
            "path": path,
            "name": os.path.basename(path),
            "size": st.st_size,
            "mime": mimetypes.guess_type(path)[0],
            "sha256": IntegrityService.hash_file(path, "sha256"),
            "sha512": IntegrityService.hash_file(path, "sha512"),
        }
