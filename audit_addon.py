import psycopg2
import datetime
from mitmproxy import http
from sitemap_service import SitemapService

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "user": "strix_user",
    "password": "strix_password",
    "dbname": "strix_pentesting"
}

class PostgresAuditAddon:
    def __init__(self, db_config=DB_CONFIG):
        self.db_config = db_config
        self.sitemap_service = SitemapService(db_config)
        self._setup_db_connection()

    def _setup_db_connection(self):
        self.conn = psycopg2.connect(**self.db_config)
        self.conn.autocommit = True

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        method = flow.request.method
        status_code = flow.response.status_code
        
        with self.conn.cursor() as cur:
            # 1. Store in requests table
            cur.execute(
                "INSERT INTO requests (url, method, status_code) VALUES (%s, %s, %s) RETURNING id",
                (url, method, status_code)
            )
            request_db_id = cur.fetchone()[0]
            
            # 2. Update Sitemap
            try:
                self.sitemap_service.insert_request(url, request_id=str(request_db_id))
            except Exception as e:
                print(f"Sitemap update error: {e}")

    def websocket_message(self, flow: http.HTTPFlow):
        if flow.websocket is None: return
        message = flow.websocket.messages[-1]
        direction = "client_to_server" if message.from_client else "server_to_client"
        
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO websocket_messages (direction, content) VALUES (%s, %s)",
                (direction, message.content)
            )

    def done(self):
        self.sitemap_service.close()
        self.conn.close()

addons = [PostgresAuditAddon()]
