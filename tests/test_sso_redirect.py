"""Unit tests for the SSO callback redirect allowlist."""

from __future__ import annotations

from wombat_server.routers.sso import _safe_frontend_url

ALLOWED = {"https://app.example.com", "https://app.example.com:8443"}


def test_allowed_origin_is_returned() -> None:
    assert _safe_frontend_url("https://app.example.com", ALLOWED) == "https://app.example.com"


def test_allowed_origin_keeps_a_safe_path() -> None:
    assert (
        _safe_frontend_url("https://app.example.com/wombat/", ALLOWED)
        == "https://app.example.com/wombat"
    )


def test_query_and_fragment_are_dropped() -> None:
    assert (
        _safe_frontend_url("https://app.example.com/wombat?next=https://evil.example", ALLOWED)
        == "https://app.example.com/wombat"
    )
    assert (
        _safe_frontend_url("https://app.example.com/wombat#fragment", ALLOWED)
        == "https://app.example.com/wombat"
    )


def test_scheme_and_host_are_normalised() -> None:
    assert (
        _safe_frontend_url("HTTPS://APP.EXAMPLE.COM/wombat", ALLOWED)
        == "https://app.example.com/wombat"
    )


def test_unknown_origin_falls_back_to_the_configured_dashboard() -> None:
    assert _safe_frontend_url("https://evil.example", ALLOWED) == "http://localhost:5173"


def test_lookalike_origin_is_rejected() -> None:
    assert _safe_frontend_url("https://app.example.com.evil", ALLOWED) == "http://localhost:5173"


def test_credentials_in_url_are_rejected() -> None:
    assert (
        _safe_frontend_url("https://user:pass@app.example.com", ALLOWED)
        == "http://localhost:5173"
    )


def test_non_http_schemes_are_rejected() -> None:
    assert _safe_frontend_url("javascript:alert(1)", ALLOWED) == "http://localhost:5173"
    assert _safe_frontend_url("//evil.example/path", ALLOWED) == "http://localhost:5173"
