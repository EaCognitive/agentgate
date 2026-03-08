"""Integration test configuration and fixtures."""

# Important: setup_env must be imported before server modules.
from tests.integration import setup_env
from tests.integration_support import build_common_fixtures
from server.routers import (
    auth_router,
    pii_router,
    policies_router,
    policy_governance_router,
)

_ = setup_env

ROUTER_SPECS = (
    (auth_router, "/api"),
    (pii_router, "/api"),
    (policy_governance_router, "/api"),
    (policies_router, "/api"),
)

(
    test_engine_fixture,
    test_app_fixture,
    auth_token_fixture,
    admin_token_fixture,
    session_fixture,
    client_fixture,
    auth_headers_fixture,
    admin_headers_fixture,
) = build_common_fixtures(ROUTER_SPECS)
