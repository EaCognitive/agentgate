"""Async HTTP client for MCP-to-REST API bridge."""

from __future__ import annotations

import logging
import os
from typing import Any, cast
from urllib.parse import quote, urlparse

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30.0
_MAX_RETRIES = 2
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_PATH_SEGMENT_SAFE_CHARS = "-._~"


class MCPApiClientError(Exception):
    """Raised when the REST API call fails."""

    def __init__(self, status_code: int, message: str, detail: Any = None):
        self.status_code = status_code
        self.message = message
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {message}")


class MCPApiClient:
    """Async authenticated client for the AgentGate REST API."""

    def __init__(self, base_url: str | None = None, token: str | None = None):
        resolved = (
            base_url
            or os.environ.get("MCP_API_URL")
            or os.environ.get("AGENTGATE_URL")
            or "http://localhost:8000"
        ).rstrip("/")
        self._validate_base_url(resolved)

        self.base_url = resolved
        self.token = token or os.environ.get("MCP_AUTH_TOKEN")
        self.refresh_token: str | None = None
        self._client: httpx.AsyncClient | None = None

    @staticmethod
    def _validate_base_url(base_url: str) -> None:
        parsed = urlparse(base_url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()

        if scheme not in {"http", "https"}:
            raise ValueError("MCP API base_url must use http or https")
        if not parsed.netloc:
            raise ValueError("MCP API base_url must include a host")
        if scheme == "http" and host not in _LOCAL_HOSTS:
            raise ValueError("MCP API base_url must use https for non-local hosts")

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_DEFAULT_TIMEOUT,
                transport=httpx.AsyncHTTPTransport(retries=_MAX_RETRIES),
            )
        return self._client

    def _require_auth(self) -> None:
        if not self.token:
            raise MCPApiClientError(
                401,
                "MCP client not authenticated. Call mcp_login or set MCP_AUTH_TOKEN.",
            )

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @staticmethod
    def _encode_path_segment(segment: str | int) -> str:
        raw = str(segment)
        if not raw:
            raise MCPApiClientError(400, "Path segment must not be empty")
        if ".." in raw or "/" in raw or "\\" in raw:
            raise MCPApiClientError(
                400,
                f"Unsafe path segment '{raw}'",
            )
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
            raise MCPApiClientError(400, "Path segment contains control characters")
        return quote(raw, safe=_PATH_SEGMENT_SAFE_CHARS)

    def path_with_segments(self, prefix: str, *segments: str | int) -> str:
        """Build a URL path from a prefix and safely encoded segments."""
        normalized_prefix = "/" + "/".join(part for part in prefix.strip("/").split("/") if part)
        encoded_segments = [self._encode_path_segment(seg) for seg in segments]
        if not encoded_segments:
            return normalized_prefix
        return f"{normalized_prefix}/{'/'.join(encoded_segments)}"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        require_auth: bool = True,
    ) -> Any:
        if require_auth:
            self._require_auth()

        client = await self._get_client()
        headers = self._auth_headers() if require_auth else None

        try:
            response = await client.request(
                method=method,
                url=path,
                params=params,
                json=body,
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise MCPApiClientError(
                0,
                f"Cannot connect to {self.base_url}: {exc}",
            ) from exc

        return self._handle_response(response)

    @staticmethod
    def _handle_response(response: httpx.Response) -> Any:
        if response.status_code == 204:
            return {}

        if response.status_code >= 400:
            detail: Any = None
            message = response.text
            try:
                detail = response.json()
                if isinstance(detail, dict):
                    raw = detail.get("detail", detail.get("message", response.text))
                    if isinstance(raw, dict):
                        message = raw.get("message", str(raw))
                    else:
                        message = str(raw)
                else:
                    message = str(detail)
            except ValueError:
                detail = None

            raise MCPApiClientError(response.status_code, message, detail)

        if not response.text:
            return {}

        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    async def login(
        self,
        email: str,
        password: str,
        totp_code: str | None = None,
        captcha_token: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate with the REST API and store session tokens."""
        payload: dict[str, Any] = {
            "email": email,
            "password": password,
        }
        if totp_code:
            payload["totp_code"] = totp_code
        if captcha_token:
            payload["captcha_token"] = captcha_token

        result_raw = await self._request(
            "POST",
            "/api/auth/login",
            body=payload,
            require_auth=False,
        )
        if not isinstance(result_raw, dict):
            raise MCPApiClientError(500, "Invalid /api/auth/login response", result_raw)
        result = cast(dict[str, Any], result_raw)
        if result.get("mfa_required"):
            return result
        access_token = result.get("access_token")
        if not access_token:
            raise MCPApiClientError(401, "Login failed: missing access token", result)

        self.token = access_token
        self.refresh_token = result.get("refresh_token")
        return result

    async def logout(self) -> dict[str, Any]:
        """Revoke tokens on the server and clear local session state."""
        remote_revoke = "skipped"
        if self.token and self.refresh_token:
            try:
                await self._request(
                    "POST",
                    "/api/auth/revoke",
                    body={"refresh_token": self.refresh_token},
                    require_auth=True,
                )
                remote_revoke = "ok"
            except MCPApiClientError:
                remote_revoke = "failed"

        self.token = None
        self.refresh_token = None
        return {"status": "logged_out", "remote_revoke": remote_revoke}

    async def whoami(self) -> dict[str, Any]:
        """Fetch the authenticated user profile from the server."""
        result = await self._request("GET", "/api/auth/me")
        if not isinstance(result, dict):
            raise MCPApiClientError(500, "Invalid /api/auth/me response", result)
        return result

    async def ensure_authenticated(self, validate_remote: bool = False) -> None:
        """Verify a token is set, optionally validating against the server."""
        self._require_auth()
        if validate_remote:
            await self.whoami()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Send an authenticated GET request to the API."""
        return await self._request("GET", path, params=params)

    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send an authenticated POST request to the API."""
        return await self._request("POST", path, body=body)

    async def put(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send an authenticated PUT request to the API."""
        return await self._request("PUT", path, body=body)

    async def patch(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send an authenticated PATCH request to the API."""
        return await self._request("PATCH", path, body=body)

    async def delete(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Send an authenticated DELETE request to the API."""
        return await self._request("DELETE", path, params=params)

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None


class _ClientState:
    """Module-level singleton state for the MCP API client."""

    instance: MCPApiClient | None = None

    @classmethod
    def get_instance(cls) -> MCPApiClient | None:
        """Return the cached API client instance, if any."""
        return cls.instance

    @classmethod
    def set_instance(cls, client: MCPApiClient | None) -> None:
        """Cache the provided API client instance."""
        cls.instance = client


def get_api_client() -> MCPApiClient:
    """Get or create the singleton MCP API client."""
    instance = _ClientState.get_instance()
    if instance is None:
        instance = MCPApiClient()
        _ClientState.set_instance(instance)
    return instance


def initialize_client(
    base_url: str | None = None,
    token: str | None = None,
) -> MCPApiClient:
    """Initialize the singleton MCP API client with explicit config."""
    instance = MCPApiClient(base_url=base_url, token=token)
    _ClientState.set_instance(instance)
    return instance


def reset_client() -> None:
    """Reset the singleton MCP API client to uninitialized state."""
    _ClientState.set_instance(None)
