-- AgentGate Database Initialization
-- This script runs automatically when the database is first created

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Set default timezone
SET timezone = 'UTC';

-- Create custom types (if needed)
-- Example: CREATE TYPE user_role AS ENUM ('admin', 'user', 'readonly');

-- Optimize for performance
ALTER DATABASE agentgate SET random_page_cost = 1.1;
ALTER DATABASE agentgate SET effective_io_concurrency = 200;

-- Enable statement statistics
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET pg_stat_statements.track = 'all';
ALTER SYSTEM SET pg_stat_statements.max = 10000;

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'AgentGate database initialized successfully';
END $$;
