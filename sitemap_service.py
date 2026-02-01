import hashlib
import psycopg2
from urllib.parse import urlparse
import uuid

class SitemapService:
    def __init__(self, db_config):
        self.conn = psycopg2.connect(**db_config)
        self.conn.autocommit = True

    def calculate_fingerprint(self, parent_id, kind, label):
        payload = f"{parent_id}:{kind}:{label}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def parse_url_to_components(self, url):
        parsed = urlparse(url)
        components = []
        
        # 1. Domain
        domain = parsed.netloc
        if domain:
            components.append(('DOMAIN', domain))
        
        # 2. Path components
        path = parsed.path.strip('/')
        if path:
            for part in path.split('/'):
                components.append(('DIRECTORY', part))
        
        # 3. Query (Optional, but Caido treats it as a node)
        if parsed.query:
            components.append(('QUERY', parsed.query))
            
        return components

    def insert_request(self, url, request_id=None, scope_id=None):
        components = self.parse_url_to_components(url)
        current_parent_id = None
        
        with self.conn.cursor() as cur:
            for i, (kind, label) in enumerate(components):
                # If it's the last component, we might want to mark it as REQUEST instead of DIRECTORY
                # unless it's a domain
                actual_kind = kind
                if i == len(components) - 1 and kind == 'DIRECTORY':
                    actual_kind = 'REQUEST'

                fingerprint = self.calculate_fingerprint(current_parent_id, actual_kind, label)
                
                # UPSERT logic
                cur.execute("""
                    INSERT INTO sitemap_entries (parent_id, scope_id, kind, label, fingerprint, last_request_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (fingerprint) DO UPDATE 
                    SET last_request_id = EXCLUDED.last_request_id,
                        created_at = NOW()
                    RETURNING id
                """, (current_parent_id, scope_id, actual_kind, label, fingerprint, request_id))
                
                node_id = cur.fetchone()[0]
                
                # Mark parent as having descendants
                if current_parent_id:
                    cur.execute("UPDATE sitemap_entries SET has_descendants = TRUE WHERE id = %s", (current_parent_id,))
                
                current_parent_id = node_id
        
        return current_parent_id

    def get_sitemap_tree(self, parent_id=None):
        with self.conn.cursor() as cur:
            if parent_id is None:
                cur.execute("SELECT id, kind, label, has_descendants FROM sitemap_entries WHERE parent_id IS NULL")
            else:
                cur.execute("SELECT id, kind, label, has_descendants FROM sitemap_entries WHERE parent_id = %s", (parent_id,))
            
            return cur.fetchall()

    def close(self):
        self.conn.close()
