CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table for Sitemap structure
CREATE TABLE IF NOT EXISTS sitemap_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parent_id UUID REFERENCES sitemap_entries(id) ON DELETE CASCADE,
    scope_id UUID,
    
    kind VARCHAR(20) NOT NULL, -- DOMAIN, DIRECTORY, REQUEST, etc.
    label TEXT NOT NULL,
    
    fingerprint CHAR(64) UNIQUE NOT NULL, 
    
    has_descendants BOOLEAN DEFAULT FALSE,
    
    last_request_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Table for HTTP Traffic
CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT,
    status_code INTEGER,
    
    -- Request Data
    request_headers TEXT,    -- Store as JSON string
    request_query TEXT,      -- Store as JSON string
    request_body BYTEA,      -- Binary data
    
    -- Response Data
    response_headers TEXT,   -- Store as JSON string
    response_body BYTEA,     -- Binary data
    content_type TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Table for WebSocket Traffic
CREATE TABLE IF NOT EXISTS websocket_messages (
    id SERIAL PRIMARY KEY,
    direction TEXT,          -- client_to_server or server_to_client
    content BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indices for performance
CREATE INDEX idx_sitemap_parent ON sitemap_entries(parent_id);
CREATE INDEX idx_sitemap_scope ON sitemap_entries(scope_id);
CREATE INDEX idx_sitemap_fingerprint ON sitemap_entries(fingerprint);
CREATE INDEX idx_requests_url ON requests(url);
CREATE INDEX idx_requests_status ON requests(status_code);
