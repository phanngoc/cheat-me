import sqlite3
import json
import datetime
import os
from mitmproxy import http

class SQLiteAuditAddon:
    def __init__(self, db_path="audit_traffic.db"):
        self.db_path = db_path
        self._setup_db()

    def _setup_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS websocket_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, direction TEXT, content BLOB)")
        conn.commit()
        conn.close()

    def response(self, flow: http.HTTPFlow):
        # Lưu HTTP bình thường
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO requests (url) VALUES (?)", (flow.request.pretty_url,))
        conn.commit()
        conn.close()

    def websocket_message(self, flow: http.HTTPFlow):
        # GHI RA FILE ĐỂ DEBUG TUYỆT ĐỐI
        with open("ws_debug_log.txt", "a") as f:
            f.write(f"WS Event triggered at {datetime.datetime.now()}\n")
            
        if flow.websocket is None: return
        message = flow.websocket.messages[-1]
        direction = "client_to_server" if message.from_client else "server_to_client"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO websocket_messages (direction, content) VALUES (?, ?)", (direction, message.content))
            conn.commit()
            conn.close()
        except Exception as e:
            with open("ws_debug_log.txt", "a") as f:
                f.write(f"SQL Error: {str(e)}\n")

addons = [SQLiteAuditAddon()]
