"""Tests for wombat_server.config startup validation."""

from __future__ import annotations

import pytest

from wombat_server.config import Settings


class TestSettingsValidation:
    def test_accepts_strong_jwt_secret_in_local(self) -> None:
        settings = Settings(
            wombat_jwt_secret="a-very-strong-random-secret-key-32-bytes",
            wombat_admin_password="admin",
        )
        assert settings.wombat_jwt_secret != "change-me-in-production"

    def test_rejects_default_jwt_secret(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wombat_jwt_secret="change-me-in-production-wombat-secret-key",
                wombat_admin_password="admin",
            )
        assert "WOMBAT_JWT_SECRET" in str(exc_info.value)

    def test_rejects_empty_jwt_secret(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wombat_jwt_secret="",
                wombat_admin_password="admin",
            )
        assert "WOMBAT_JWT_SECRET" in str(exc_info.value)

    def test_rejects_change_me_placeholder(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wombat_jwt_secret="change-me-in-production",
                wombat_admin_password="admin",
            )
        assert "WOMBAT_JWT_SECRET" in str(exc_info.value)

    def test_requires_encryption_key_in_non_local(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wombat_env="staging",
                wombat_jwt_secret="a-very-strong-random-secret-key-32-bytes",
                wombat_admin_password="admin",
            )
        assert "WOMBAT_ENCRYPTION_KEY" in str(exc_info.value)

    def test_allows_non_local_with_encryption_key(self) -> None:
        settings = Settings(
            wombat_env="staging",
            wombat_jwt_secret="a-very-strong-random-secret-key-32-bytes",
            wombat_admin_password="a-strong-bootstrap-password",
            wombat_encryption_key="a" * 32,
            wombat_cookie_secure=True,
        )
        assert settings.wombat_env == "staging"
