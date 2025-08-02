-- Create the agent_data table for tracking agent information
CREATE TABLE IF NOT EXISTS agent_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    hostname VARCHAR(100) NOT NULL,
    local_ip VARCHAR(100) NOT NULL,
    public_ip VARCHAR(100) NOT NULL,
    os_info VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NULL DEFAULT NULL
);

-- Add indices for faster querying
CREATE INDEX idx_agent_data_timestamp ON agent_data(timestamp);
CREATE INDEX idx_agent_data_created_at ON agent_data(created_at);