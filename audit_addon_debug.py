import sqlite3
import json
import datetime

class UniversalAuditAddon:
    def __init__(self, db_path="audit_traffic.db"):
        self.db_path = db_path
        self._setup_db()

    def _setup_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, timestamp TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS websocket_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT, timestamp TEXT)")
        conn.commit()
        conn.close()

    def response(self, flow):
        # HTTP capture works fine
        pass

    # Thử bắt mọi event có liên quan đến websocket
    def websocket_message(self, flow):
        msg = flow.messages[-1].content
        print(f"DEBUG: websocket_message called! Content: {msg[:20]}")
        self._save_ws(str(msg))

    def _save_ws(self, content):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO websocket_messages (content, timestamp) VALUES (?, ?)", (content, datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()

addons = [UniversalAuditAddon()]
