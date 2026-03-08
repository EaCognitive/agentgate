"""Environment setup for integration tests."""

import os

# Set environment variables before importing server modules
os.environ["REDIS_URL"] = "memory://"
os.environ["AGENTGATE_ENV"] = "test"
os.environ["SECRET_KEY"] = "test-secret-key-for-integration-tests-32characters"
os.environ["TESTING"] = "true"
