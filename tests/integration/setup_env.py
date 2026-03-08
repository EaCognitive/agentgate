"""Environment setup for integration tests."""

import os

os.environ["REDIS_URL"] = "memory://"
os.environ["AGENTGATE_ENV"] = "development"
os.environ["SECRET_KEY"] = "test-secret-key-for-integration-tests-32characters"
os.environ["TESTING"] = "true"
