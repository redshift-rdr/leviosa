import argparse
import re
from dataclasses import replace
from urllib.parse import urlparse, urlunparse

from core.analysers import RegexAnalyser
from modules import pathfuzz


class SensitiveFiles(pathfuzz.PathFuzzer):
    """
    Common sensitive file / directory discovery.

    Reuses PathFuzzer's recursive path fuzzing: for every depth level of the
    input path, each candidate sensitive path is appended to the prefix at that
    level. e.g. for an input path /app/api/v1 the module probes:

        /.git/config,  /.env,  /.htaccess, ...
        /app/.git/config,  /app/.env, ...
        /app/api/.git/config,  /app/api/.env, ...
        /app/api/v1/.git/config,  /app/api/v1/.env, ...

    This finds artefacts (VCS metadata, dotfiles, backups, config, key
    material) exposed at *any* directory level of a deployment, not just the
    web root.

    Unlike PathFuzzer's own recursive mode, entries carry their own trailing
    slash: directory entries in the wordlist end with "/", file entries do not,
    so files are not requested with a spurious trailing "/".

    A curated built-in wordlist is used by default. Replace it with
    --sensitive-wordlist, or add extra paths with --sensitive-extra.
    """

    # Directory entries end with "/"; file entries do not.
    DEFAULT_SENSITIVE_PATHS = [
        # Version control
        ".git/",
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/logs/HEAD",
        ".gitignore",
        ".gitlab-ci.yml",
        ".svn/",
        ".svn/entries",
        ".svn/wc.db",
        ".hg/",
        ".bzr/",
        # Environment / secrets
        ".env",
        ".env.local",
        ".env.dev",
        ".env.prod",
        ".env.production",
        ".env.backup",
        ".env.bak",
        ".env.save",
        ".aws/credentials",
        ".npmrc",
        "secrets.json",
        "credentials",
        "credentials.json",
        # Web server config / auth
        ".htaccess",
        ".htpasswd",
        "web.config",
        "nginx.conf",
        "httpd.conf",
        # App config
        "config.php",
        "config.php.bak",
        "config.inc.php",
        "wp-config.php",
        "wp-config.php.bak",
        "settings.py",
        "application.properties",
        "config.yml",
        "config.yaml",
        "config.json",
        "composer.json",
        "composer.lock",
        "package.json",
        # Backups / dumps
        "backup.zip",
        "backup.tar.gz",
        "backup.sql",
        "db.sql",
        "dump.sql",
        "database.sql",
        "site.zip",
        "www.zip",
        # Key material / shell history
        ".ssh/",
        ".ssh/id_rsa",
        ".ssh/authorized_keys",
        "id_rsa",
        ".bash_history",
        # CI / container / IDE
        ".dockerignore",
        "Dockerfile",
        "docker-compose.yml",
        ".travis.yml",
        ".idea/",
        ".vscode/",
        # Server info / misc
        ".DS_Store",
        "phpinfo.php",
        "info.php",
        "server-status",
        "error_log",
        "access_log",
        "WEB-INF/web.xml",
        ".well-known/security.txt",
    ]

    # Overrides PathFuzzer.needs_body: content signatures below inspect bodies.
    needs_body = True

    def __init__(self):
        super().__init__()
        # Recursion at every path level is the whole point of this module.
        self._recursive = True
        self._wordlist = list(self.DEFAULT_SENSITIVE_PATHS)
        # Content signatures that confirm an exposure (over and above a
        # non-404 status). Reuses the inherited _skip analyser for filtering.
        self._content_flags = [
            ("git-repo", RegexAnalyser(
                r"(\[core\]|ref:\s*refs/|repositoryformatversion)", re.IGNORECASE)),
            ("private-key", RegexAnalyser(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
            ("env-secrets", RegexAnalyser(
                r"(?mi)^\s*(DB_|APP_|AWS_|SECRET|API[_A-Z]*KEY|PASSWORD|TOKEN)\S*\s*=")),
            ("htpasswd", RegexAnalyser(r":\$(apr1|2[aby]|1|5|6)\$")),
            ("sql-dump", RegexAnalyser(
                r"(?i)\b(CREATE TABLE|INSERT INTO|DROP TABLE)\b")),
        ]

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="sensitivefiles", add_help=False)
        parser.add_argument(
            "--sensitive-wordlist", metavar="PATH", default=None,
            help="Replace the built-in sensitive path list with entries from this "
                 "file (one path per line; end directories with '/')",
        )
        parser.add_argument(
            "--sensitive-extra", metavar="PATH", default=None,
            help="Append the paths in this file on top of the built-in list",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)

        if parsed.sensitive_wordlist:
            self._wordlist = self._read_paths(parsed.sensitive_wordlist)
        else:
            self._wordlist = list(self.DEFAULT_SENSITIVE_PATHS)

        if parsed.sensitive_extra:
            self._wordlist.extend(self._read_paths(parsed.sensitive_extra))

        self.parse_request_filters(args)

    @staticmethod
    def _read_paths(path: str) -> list[str]:
        # Strip leading slashes but preserve a trailing slash (dir marker).
        with open(path) as f:
            return [line.strip().lstrip("/") for line in f if line.strip()]

    async def mutate(self, requests, context):
        if not self._wordlist:
            raise RuntimeError(
                "sensitivefiles has no paths to test. Provide --sensitive-wordlist "
                "with a non-empty file, or omit it to use the built-in list."
            )
        return await super().mutate(requests, context)

    def _recursive_variants(self, req):
        """
        Build one variant per (path depth × wordlist entry). Overrides
        PathFuzzer's version so that wordlist entries keep their own trailing
        slash instead of always having one appended.
        """
        parsed = urlparse(req.url)
        segments = [s for s in parsed.path.rstrip("/").split("/") if s]
        # Probe every level from the root down to and including the full input
        # path (len(segments) + 1 levels); range(1) covers a bare-domain URL.
        seen = set()
        for depth in range(len(segments) + 1):
            prefix = "/" + "/".join(segments[:depth]) if segments[:depth] else ""
            for word in self._wordlist:
                fuzz_path = f"{prefix}/{word}"
                url = urlunparse(parsed._replace(
                    path=fuzz_path, params="", query="", fragment=""))
                if url in seen:
                    continue
                seen.add(url)
                # url-only mutation, safe to alias the unmutated headers/params.
                yield replace(req, url=url)

    async def analyze_one(self, response, context):
        if self._skip.matches(response):
            return
        flags = [name for name, an in self._content_flags if an.matches(response)]
        suffix = f"  [exposed: {', '.join(flags)}]" if flags else ""
        print(
            f"[SENSITIVEFILES] {response.status} {response.request.method} "
            f"{response.request.url}{suffix}"
        )
