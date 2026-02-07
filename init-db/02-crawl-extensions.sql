-- Crawl Queue Extensions
-- Additional tables for the auto-crawling system

-- ============================================
-- Crawl Queue Table
-- Manages URLs to be crawled with priority
-- ============================================
CREATE TABLE IF NOT EXISTS crawl_queue (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    fingerprint CHAR(64) UNIQUE NOT NULL,
    priority INTEGER DEFAULT 5 CHECK (priority >= 1 AND priority <= 5),
    depth INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'skipped')),

    -- Discovery tracking
    discovered_from_url TEXT,
    discovered_from_request_id INTEGER REFERENCES requests(id),

    -- Retry handling
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,

    -- Session tracking
    session_id UUID
);

-- Indices for crawl queue
CREATE INDEX idx_crawl_queue_status ON crawl_queue(status);
CREATE INDEX idx_crawl_queue_priority ON crawl_queue(priority, created_at);
CREATE INDEX idx_crawl_queue_session ON crawl_queue(session_id);
CREATE INDEX idx_crawl_queue_fingerprint ON crawl_queue(fingerprint);


-- ============================================
-- Discovered Links Table
-- Tracks all links found during crawling
-- ============================================
CREATE TABLE IF NOT EXISTS discovered_links (
    id SERIAL PRIMARY KEY,
    source_request_id INTEGER REFERENCES requests(id),
    source_url TEXT NOT NULL,
    target_url TEXT NOT NULL,
    fingerprint CHAR(64) NOT NULL,

    -- Link metadata
    link_type VARCHAR(30) CHECK (link_type IN ('anchor', 'form', 'script', 'stylesheet', 'api_doc', 'javascript', 'redirect', 'iframe', 'image', 'media')),
    anchor_text TEXT,
    context TEXT,

    -- Priority scoring
    priority INTEGER DEFAULT 5,
    rule_score FLOAT,
    tfidf_score FLOAT,
    q_score FLOAT,

    -- Status
    crawled BOOLEAN DEFAULT FALSE,
    crawled_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indices for discovered links
CREATE INDEX idx_discovered_links_source ON discovered_links(source_request_id);
CREATE INDEX idx_discovered_links_target ON discovered_links(target_url);
CREATE INDEX idx_discovered_links_crawled ON discovered_links(crawled);
CREATE INDEX idx_discovered_links_priority ON discovered_links(priority);


-- ============================================
-- Business Flows Table
-- Detected business flows and security test results
-- ============================================
CREATE TABLE IF NOT EXISTS business_flows (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES requests(id),
    url TEXT NOT NULL,

    -- Flow classification
    flow_type VARCHAR(50) NOT NULL CHECK (flow_type IN (
        'authentication', 'registration', 'password_reset',
        'e_commerce', 'payment', 'user_management',
        'admin_panel', 'api_endpoint', 'file_upload',
        'search', 'data_export', 'settings'
    )),
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1),

    -- Detection details
    indicators JSONB,
    form_data JSONB,

    -- Test results
    suggested_tests JSONB,
    test_results JSONB,
    vulnerabilities_found JSONB,

    -- Status
    analyzed BOOLEAN DEFAULT FALSE,
    analyzed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indices for business flows
CREATE INDEX idx_business_flows_request ON business_flows(request_id);
CREATE INDEX idx_business_flows_type ON business_flows(flow_type);
CREATE INDEX idx_business_flows_priority ON business_flows(priority);
CREATE INDEX idx_business_flows_analyzed ON business_flows(analyzed);


-- ============================================
-- Crawl Sessions Table
-- Tracks crawl sessions for resumability
-- ============================================
CREATE TABLE IF NOT EXISTS crawl_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed', 'failed')),

    -- Configuration
    seed_urls JSONB NOT NULL,
    allowed_domains JSONB,
    max_depth INTEGER DEFAULT 3,
    max_urls INTEGER DEFAULT 1000,

    -- Statistics
    urls_queued INTEGER DEFAULT 0,
    urls_crawled INTEGER DEFAULT 0,
    urls_failed INTEGER DEFAULT 0,
    links_discovered INTEGER DEFAULT 0,
    flows_detected INTEGER DEFAULT 0,

    -- Q-learning model state
    q_model_path TEXT,

    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    paused_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    notes TEXT
);


-- ============================================
-- Q-Learning Features Table
-- Stores learned feature weights for link prioritization
-- ============================================
CREATE TABLE IF NOT EXISTS q_learning_features (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES crawl_sessions(id),

    feature_name VARCHAR(100) NOT NULL,
    feature_weight FLOAT DEFAULT 0.5,

    -- Statistics
    positive_updates INTEGER DEFAULT 0,
    negative_updates INTEGER DEFAULT 0,

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(session_id, feature_name)
);

-- Index for Q-learning features
CREATE INDEX idx_q_features_session ON q_learning_features(session_id);
CREATE INDEX idx_q_features_weight ON q_learning_features(feature_weight DESC);


-- ============================================
-- Security Findings Table
-- Stores detected security issues
-- ============================================
CREATE TABLE IF NOT EXISTS security_findings (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES requests(id),
    flow_id INTEGER REFERENCES business_flows(id),

    -- Finding details
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    description TEXT,

    -- Evidence
    evidence JSONB,
    affected_parameter TEXT,
    payload_used TEXT,

    -- Reproduction
    reproduction_steps JSONB,

    -- Status
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false_positive', 'fixed')),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Indices for security findings
CREATE INDEX idx_security_findings_request ON security_findings(request_id);
CREATE INDEX idx_security_findings_flow ON security_findings(flow_id);
CREATE INDEX idx_security_findings_severity ON security_findings(severity);
CREATE INDEX idx_security_findings_type ON security_findings(finding_type);
CREATE INDEX idx_security_findings_status ON security_findings(status);


-- ============================================
-- Helper Views
-- ============================================

-- View for pending crawl tasks with priority
CREATE OR REPLACE VIEW pending_crawl_tasks AS
SELECT
    cq.id,
    cq.url,
    cq.priority,
    cq.depth,
    cq.discovered_from_url,
    cq.created_at
FROM crawl_queue cq
WHERE cq.status = 'pending'
ORDER BY cq.priority ASC, cq.created_at ASC;

-- View for high-priority business flows
CREATE OR REPLACE VIEW critical_flows AS
SELECT
    bf.id,
    bf.url,
    bf.flow_type,
    bf.confidence,
    bf.indicators,
    r.method,
    r.status_code
FROM business_flows bf
JOIN requests r ON bf.request_id = r.id
WHERE bf.priority IN ('critical', 'high')
ORDER BY bf.priority, bf.confidence DESC;

-- View for session statistics
CREATE OR REPLACE VIEW session_stats AS
SELECT
    cs.id,
    cs.name,
    cs.status,
    cs.urls_crawled,
    cs.urls_failed,
    cs.links_discovered,
    cs.flows_detected,
    COUNT(DISTINCT sf.id) as security_findings,
    cs.started_at,
    cs.completed_at,
    EXTRACT(EPOCH FROM (COALESCE(cs.completed_at, NOW()) - cs.started_at)) as duration_seconds
FROM crawl_sessions cs
LEFT JOIN business_flows bf ON bf.request_id IN (
    SELECT r.id FROM requests r
    JOIN crawl_queue cq ON cq.url = r.url
    WHERE cq.session_id = cs.id
)
LEFT JOIN security_findings sf ON sf.flow_id = bf.id
GROUP BY cs.id;
