from PySide6.QtWidgets import QTableWidget

class DataTable(QTableWidget):
    def __init__(self, headers):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setAlternatingRowColors(True)
