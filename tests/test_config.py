import pytest
from cognic_tool_oracle_schema.config import Config, ConfigError


def _set_min_oracle_env(monkeypatch):
    """Set the minimal env for ``Config.from_env()`` to SUCCEED by default.

    Sets DSN/USER/PASSWORD_FILE plus ``COGNIC_AUTH_MODE=dev_insecure`` +
    ``COGNIC_ENV=dev`` so the ``jwt``-mode oauth-triple requirement does not
    fire. Optional vars that could leak from the ambient environment and break
    a success-path test are defensively cleared; individual failure tests
    override the specific var under test after calling this helper.
    """
    monkeypatch.setenv("COGNIC_ORACLE_DSN", "localhost:1521/XEPDB1")
    monkeypatch.setenv("COGNIC_ORACLE_USER", "ro_user")
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD_FILE", "/run/secrets/oracle-password")
    monkeypatch.delenv("COGNIC_ORACLE_PASSWORD", raising=False)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    for _leak in (
        "COGNIC_ORACLE_ALLOWED_OWNERS",
        "COGNIC_ORACLE_MAX_ROWS",
        "COGNIC_ORACLE_POOL_MAX",
        "COGNIC_REQUIRED_SCOPES",
        "COGNIC_OAUTH_ISSUER",
        "COGNIC_OAUTH_JWKS_URI",
        "COGNIC_OAUTH_AUDIENCE",
    ):
        monkeypatch.delenv(_leak, raising=False)


def test_from_env_parses_oracle_and_auth(monkeypatch):
    for k, v in {
        "COGNIC_ORACLE_DSN": "localhost:1521/XEPDB1",
        "COGNIC_ORACLE_USER": "ro_user",
        "COGNIC_ORACLE_PASSWORD_FILE": "/run/secrets/oracle-password",
        "COGNIC_ORACLE_ALLOWED_OWNERS": "HR, SALES",
        "COGNIC_ORACLE_MAX_ROWS": "50",
        "COGNIC_OAUTH_ISSUER": "https://as.example/",
        "COGNIC_OAUTH_JWKS_URI": "https://as.example/.well-known/jwks.json",
        "COGNIC_OAUTH_AUDIENCE": "http://127.0.0.1:8765/mcp",
        "COGNIC_REQUIRED_SCOPES": "oracle_schema.read",
        "COGNIC_AUTH_MODE": "jwt",
    }.items():
        monkeypatch.setenv(k, v)
    cfg = Config.from_env()
    assert cfg.oracle_password_file == "/run/secrets/oracle-password"
    assert cfg.allowed_owners == frozenset({"HR", "SALES"})
    assert cfg.max_rows == 50
    assert cfg.required_scopes == frozenset({"oracle_schema.read"})


def test_max_rows_clamped_to_hard_cap(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_ORACLE_MAX_ROWS", "99999")
    assert Config.from_env().max_rows == 1000


def test_jwt_mode_requires_oauth_fields(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "jwt")
    monkeypatch.delenv("COGNIC_OAUTH_ISSUER", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_dev_insecure_only_in_dev_env(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.delenv("COGNIC_ENV", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_required_scopes_cannot_be_empty(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.setenv("COGNIC_AUTH_MODE", "dev_insecure")
    monkeypatch.setenv("COGNIC_ENV", "dev")
    monkeypatch.setenv("COGNIC_REQUIRED_SCOPES", " , ")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_password_file_is_required(monkeypatch):
    _set_min_oracle_env(monkeypatch)
    monkeypatch.delenv("COGNIC_ORACLE_PASSWORD_FILE")

    with pytest.raises(ConfigError, match="missing required env COGNIC_ORACLE_PASSWORD_FILE"):
        Config.from_env()


@pytest.mark.parametrize("password_file_present", [False, True])
def test_legacy_password_env_is_always_refused(monkeypatch, password_file_present):
    _set_min_oracle_env(monkeypatch)
    if not password_file_present:
        monkeypatch.delenv("COGNIC_ORACLE_PASSWORD_FILE")
    monkeypatch.setenv("COGNIC_ORACLE_PASSWORD", "retired-channel-value")

    with pytest.raises(ConfigError, match="COGNIC_ORACLE_PASSWORD was removed in v0.5.0"):
        Config.from_env()
