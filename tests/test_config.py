import pytest
from core.config import Config, load_config


class TestConfigDefaults:
    def test_no_proxy_default(self):
        assert Config().no_proxy is False

    def test_proxy_url_default(self):
        assert Config().proxy_url is None

    def test_burp_host(self):
        assert Config().burp_host == "127.0.0.1"

    def test_burp_port(self):
        assert Config().burp_port == 8080

    def test_log_enabled_default(self):
        assert Config().log_enabled is True

    def test_log_db_path_default(self):
        assert Config().log_db_path == "leviosa.db"

    def test_concurrency(self):
        assert Config().concurrency == 20

    def test_max_body_bytes(self):
        assert Config().max_body_bytes == 1_048_576

    def test_timeout(self):
        assert Config().timeout == 30

    def test_follow_redirects_default(self):
        assert Config().follow_redirects is False

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
        assert config.no_proxy is False
        assert config.concurrency == 20

    def test_burp_host_and_port(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text('[burp]\nhost = "10.0.0.1"\nport = 9090\n')
        config = load_config(str(f))
        assert config.burp_host == "10.0.0.1"
        assert config.burp_port == 9090

    def test_proxy_url(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text('[proxy]\nurl = "http://127.0.0.1:8081"\n')
        config = load_config(str(f))
        assert config.proxy_url == "http://127.0.0.1:8081"

    def test_log_settings(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text('[log]\nenabled = false\npath = "/tmp/custom.db"\n')
        config = load_config(str(f))
        assert config.log_enabled is False
        assert config.log_db_path == "/tmp/custom.db"

    def test_concurrency_limit(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[concurrency]\nlimit = 5\n")
        config = load_config(str(f))
        assert config.concurrency == 5

    def test_unset_fields_keep_defaults(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[burp]\nport = 9090\n")
        config = load_config(str(f))
        assert config.burp_host == "127.0.0.1"
        assert config.burp_port == 9090

    def test_empty_toml_returns_defaults(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("")
        config = load_config(str(f))
        assert config.no_proxy is False
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

    def test_follow_redirects(self, tmp_path):
        f = tmp_path / "leviosa.toml"
        f.write_text("[request]\nfollow_redirects = true\n")
        config = load_config(str(f))
        assert config.follow_redirects is True
