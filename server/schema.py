import strawberry
from typing import List, Optional
from .db import database
from .models import Request, SitemapEntry

@strawberry.type
class Query:
    @strawberry.field
    async def request(self, id: int) -> Optional[Request]:
        query = "SELECT * FROM requests WHERE id = :id"
        row = await database.fetch_one(query=query, values={"id": id})
        if not row:
            return None
            
        import base64
        return Request(
            id=row["id"],
            url=row["url"],
            method=row["method"],
            status_code=row["status_code"],
            request_headers=row["request_headers"],
            request_query=row["request_query"],
            request_body=base64.b64encode(row["request_body"]).decode('utf-8') if row["request_body"] else None,
            response_headers=row["response_headers"],
            response_body=base64.b64encode(row["response_body"]).decode('utf-8') if row["response_body"] else None,
            content_type=row["content_type"],
            created_at=row["created_at"]
        )

    @strawberry.field
    async def requests(
        self, 
        status: Optional[int] = None, 
        url_contains: Optional[str] = None,
        method: Optional[str] = None
    ) -> List[Request]:
        query = "SELECT * FROM requests WHERE 1=1"
        values = {}
        
        if status is not None:
            query += " AND status_code = :status"
            values["status"] = status
            
        if method is not None:
            query += " AND method = :method"
            values["method"] = method.upper()

        if url_contains is not None:
            query += " AND url LIKE :url_contains"
            values["url_contains"] = f"%{url_contains}%"
            
        rows = await database.fetch_all(query=query, values=values)
        import base64
        return [
            Request(
                id=row["id"],
                url=row["url"],
                method=row["method"],
                status_code=row["status_code"],
                request_headers=row["request_headers"],
                request_query=row["request_query"],
                request_body=base64.b64encode(row["request_body"]).decode('utf-8') if row["request_body"] else None,
                response_headers=row["response_headers"],
                response_body=base64.b64encode(row["response_body"]).decode('utf-8') if row["response_body"] else None,
                content_type=row["content_type"],
                created_at=row["created_at"]
            ) for row in rows
        ]

    @strawberry.field
    async def sitemap_entries(self, parent_id: Optional[str] = None) -> List[SitemapEntry]:
        if parent_id:
            query = "SELECT id, parent_id, scope_id, kind, label, fingerprint, has_descendants, last_request_id, created_at FROM sitemap_entries WHERE parent_id = :parent_id"
            rows = await database.fetch_all(query=query, values={"parent_id": parent_id})
        else:
            query = "SELECT id, parent_id, scope_id, kind, label, fingerprint, has_descendants, last_request_id, created_at FROM sitemap_entries WHERE parent_id IS NULL"
            rows = await database.fetch_all(query=query)
        return [SitemapEntry(**dict(row)) for row in rows]

    @strawberry.field
    async def sitemap_descendants(self, parent_id: str) -> List[SitemapEntry]:
        # Recursive CTE to find all children, grandchildren, etc.
        query = """
        WITH RECURSIVE descendants AS (
            SELECT id, parent_id, scope_id, kind, label, fingerprint, has_descendants, last_request_id, created_at
            FROM sitemap_entries
            WHERE id = :parent_id
            UNION ALL
            SELECT s.id, s.parent_id, s.scope_id, s.kind, s.label, s.fingerprint, s.has_descendants, s.last_request_id, s.created_at
            FROM sitemap_entries s
            JOIN descendants d ON s.parent_id = d.id
        )
        SELECT * FROM descendants WHERE id != :parent_id;
        """
        rows = await database.fetch_all(query=query, values={"parent_id": parent_id})
        return [SitemapEntry(**dict(row)) for row in rows]

schema = strawberry.Schema(query=Query)
