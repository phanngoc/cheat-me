import strawberry
from typing import Optional
from datetime import datetime

@strawberry.type
class Request:
    id: int
    url: str
    method: str
    status_code: Optional[int]
    request_headers: Optional[str]
    request_query: Optional[str]
    request_body: Optional[str]
    response_headers: Optional[str]
    response_body: Optional[str]
    content_type: Optional[str]
    created_at: datetime

@strawberry.type
class SitemapEntry:
    id: str  # UUID
    parent_id: Optional[str]
    scope_id: Optional[str]
    kind: str
    label: str
    fingerprint: str
    has_descendants: bool
    last_request_id: Optional[str]
    created_at: datetime

@strawberry.type
class WebSocketMessage:
    id: int
    direction: str
    content: str # Base64 or string representation
    created_at: datetime
