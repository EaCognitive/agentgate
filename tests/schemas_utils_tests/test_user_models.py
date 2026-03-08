"""Tests for User models."""

from datetime import timedelta

from server.models.schemas import RefreshToken, UserBase, UserCreate, UserRead, utc_now


class TestUserModels:
    """Test User-related model classes."""

    def test_user_base_creation(self, sample_user_data):
        """Test UserBase model creation."""
        user_base = UserBase(**sample_user_data)

        assert user_base.email == "test@example.com"
        assert user_base.name == "Test User"
        assert user_base.role == "viewer"

    def test_user_base_defaults(self):
        """Test UserBase default values."""
        user_base = UserBase(email="test@example.com")

        assert user_base.email == "test@example.com"
        assert user_base.name is None
        assert user_base.role == "viewer"

    def test_user_create_validation(self):
        """Test UserCreate model validation."""
        user_create = UserCreate(email="test@example.com", password="password123", name="Test User")

        assert user_create.email == "test@example.com"
        assert user_create.password == "password123"
        assert user_create.name == "Test User"

    def test_user_create_minimal(self):
        """Test UserCreate with minimal required fields."""
        user_create = UserCreate(email="test@example.com", password="password123")

        assert user_create.email == "test@example.com"
        assert user_create.password == "password123"
        assert user_create.name is None

    def test_user_read_structure(self):
        """Test UserRead model structure."""
        now = utc_now()
        user_read = UserRead(
            id=1,
            email="test@example.com",
            name="Test User",
            role="viewer",
            is_active=True,
            created_at=now,
            totp_enabled=False,
        )

        assert user_read.id == 1
        assert user_read.email == "test@example.com"
        assert user_read.is_active is True
        assert user_read.totp_enabled is False
        assert user_read.created_at == now

    def test_refresh_token_structure(self):
        """Test RefreshToken model structure."""
        now = utc_now()
        expires = now + timedelta(days=7)

        token = RefreshToken(
            token="refresh-token-123", user_id=1, expires_at=expires, created_at=now, revoked=False
        )

        assert token.token == "refresh-token-123"
        assert token.user_id == 1
        assert token.expires_at == expires
        assert token.revoked is False
