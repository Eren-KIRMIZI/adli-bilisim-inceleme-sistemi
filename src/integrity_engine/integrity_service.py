import hashlib, os

class IntegrityService:
    @staticmethod
    def hash_file(path, algo="sha256"):
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def verify(path, expected, algo="sha256"):
        return IntegrityService.hash_file(path, algo).lower() == expected.lower()
