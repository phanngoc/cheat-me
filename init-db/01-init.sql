CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS sitemap_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parent_id UUID REFERENCES sitemap_entries(id) ON DELETE CASCADE,
    scope_id UUID,
    
    kind VARCHAR(20) NOT NULL,
    label TEXT NOT NULL,
    
    fingerprint CHAR(64) UNIQUE NOT NULL, 
    
    has_descendants BOOLEAN DEFAULT FALSE,
    
    last_request_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT,
    status_code INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS websocket_messages (
    id SERIAL PRIMARY KEY,
    direction TEXT,
    content BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sitemap_parent ON sitemap_entries(parent_id);
CREATE INDEX idx_sitemap_scope ON sitemap_entries(scope_id);
CREATE INDEX idx_sitemap_fingerprint ON sitemap_entries(fingerprint);
