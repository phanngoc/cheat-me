from mitmproxy import websocket, http
import sqlite3
import datetime

class DebugWS:
    def websocket_start(self, flow: websocket.WebSocketFlow):
        print(f"[DEBUG] WebSocket started: {flow.handshake_flow.request.pretty_url}")

    def websocket_message(self, flow: websocket.WebSocketFlow):
        message = flow.messages[-1]
        print(f"[DEBUG] WebSocket message: {message.content[:50]}")
        
        # Save to DB as well for proof
        conn = sqlite3.connect("audit_traffic.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS ws_debug (info TEXT)")
        cursor.execute("INSERT INTO ws_debug VALUES (?)", (str(message.content),))
        conn.commit()
        conn.close()

addons = [DebugWS()]
