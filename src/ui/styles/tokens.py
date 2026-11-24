LIGHT = {
 "bg":"#F5F5F7","surface":"#FFFFFF","text":"#1D2733","muted":"#667085",
 "accent":"#315C85","verified":"#26845B","warning":"#B9822D","critical":"#C34C4C"}
DARK = {
 "bg":"#121417","surface":"#1E2126","text":"#E8EAF0","muted":"#9AA3B2",
 "accent":"#5B8DB8","verified":"#3FB07A","warning":"#D4A04A","critical":"#E07070"}
def qss(theme):
    t = LIGHT if theme=="light" else DARK
    return f"""
QWidget {{ background:{t['bg']}; color:{t['text']}; font-family:Segoe UI; font-size:13px; }}
QFrame {{ background:{t['surface']}; border:1px solid #D0D5DD; border-radius:8px; }}
QPushButton {{ background:{t['accent']}; color:white; border:none; padding:6px 12px; border-radius:6px; }}
QTableWidget {{ gridline-color:#D0D5DD; }}
QHeaderView::section {{ background:{t['surface']}; padding:4px; }}
QLineEdit, QTextEdit {{ background:{t['surface']}; border:1px solid #D0D5DD; padding:4px; border-radius:6px; }}
"""
