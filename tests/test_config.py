import pytest
from core.config import Config, load_config


class TestConfigDefaults:
    def test_proxy_enabled(self):
        assert Config().proxy_enabled is True

    def test_proxy_host(self):
        assert Config().proxy_host == "127.0.0.1"

    def test_proxy_port(self):
        assert Config().proxy_port == 8080

    def test_concurrency(self):
        assert Config().concurrency == 20

    def test_max_body_bytes(self):
        assert Config().max_body_bytes == 1_048_576

    def test_timeout(self):
        assert Config().timeout == 30

    def test_modules_empty(self):
        assert Config().modules == []

    def test_verbose_false(self):
        assert Config().verbose is False

    def test_modules_not_shared_default(self):
        c1 = Config()
        c2 = Config()
        c1.modules.append("foo")
        assert c2.modules == []


class TestLoadConfig:
    def test_missing_toml_returns_defaults(self):
        config = load_config("/nonexistent/leviosa.toml")
        assert config.proxy_enabled is True
        assert config.concurrency == 20

    def test_proxy_host_and_port(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text('[proxy]\nhost = "10.0.0.1"\nport = 9090\n')
        config = load_config(str(f))
        assert config.proxy_host == "10.0.0.1"
        assert config.proxy_port == 9090

    def test_proxy_disabled(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[proxy]\nenabled = false\n")
        config = load_config(str(f))
        assert config.proxy_enabled is False

    def test_concurrency_limit(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[concurrency]\nlimit = 5\n")
        config = load_config(str(f))
        assert config.concurrency == 5

    def test_unset_fields_keep_defaults(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[proxy]\nport = 9090\n")
        config = load_config(str(f))
        assert config.proxy_host == "127.0.0.1"
        assert config.proxy_port == 9090

    def test_empty_toml_returns_defaults(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("")
        config = load_config(str(f))
        assert config.proxy_enabled is True
        assert config.concurrency == 20

    def test_body_max_bytes(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[body]\nmax_bytes = 2048\n")
        config = load_config(str(f))
        assert config.max_body_bytes == 2048

    def test_request_timeout(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[request]\ntimeout = 5\n")
        config = load_config(str(f))
        assert config.timeout == 5
