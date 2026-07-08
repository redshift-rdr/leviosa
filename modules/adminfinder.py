import argparse
import re
from dataclasses import replace
from urllib.parse import urlparse, urlunparse

from core.analysers import HeaderAnalyser, RegexAnalyser, StatusCodeAnalyser
from modules import pathfuzz


class AdminFinder(pathfuzz.PathFuzzer):
    """
    Common administrative interface discovery via path fuzzing.

    Reuses PathFuzzer's keyword-substitution machinery: for each input request
    the target's origin (scheme://host[:port]) is taken and each candidate admin
    path from the wordlist is appended, e.g.

        http://target/anything  ->  http://target/admin
                                     http://target/administrator
                                     http://target/wp-admin/
                                     ...

    A curated built-in wordlist of common admin paths is used by default. Pass
    --admin-wordlist to replace it, or --admin-extra to append extra paths on top
    of the built-in list.

    Responses are reported when they are not obvious misses (404 / network error)
    and are additionally flagged when they look like a real admin interface:
    an auth challenge (401 + WWW-Authenticate) or a login/admin page body.
    """

    # Curated list of frequently-seen administrative interface paths.
    DEFAULT_ADMIN_PATHS = [
        "admin",
        "admin/",
        "admin/login",
        "admin/login.php",
        "admin/index.php",
        "admin.php",
        "administrator",
        "administrator/",
        "administration",
        "adminpanel",
        "admin-panel",
        "admin_area",
        "adminarea",
        "controlpanel",
        "control",
        "cpanel",
        "cp",
        "backend",
        "manage",
        "manager",
        "management",
        "console",
        "dashboard",
        "webadmin",
        "sysadmin",
        "moderator",
        "login",
        "login.php",
        "signin",
        "auth",
        "user/login",
        "users/login",
        "account/login",
        "wp-admin/",
        "wp-login.php",
        "wp-admin/login.php",
        "phpmyadmin/",
        "pma/",
        "adminer.php",
        "django-admin/",
        "admin/dashboard",
        "umbraco/",
        "typo3/",
        "ghost/",
        "joomla/administrator/",
        "system/",
        "config/",
        "settings/",
    ]

    # Overrides PathFuzzer.needs_body: the body analysers below inspect response
    # content, so the engine must read bodies.
    needs_body = True

    def __init__(self):
        super().__init__()
        # AdminFinder builds URLs from the origin rather than a keyword in the
        # input URL, so recursion is never used and the keyword is a private
        # sentinel that will not collide with real path content.
        self._keyword = "\x00ADMINFUZZ\x00"
        self._recursive = False
        self._wordlist = list(self.DEFAULT_ADMIN_PATHS)
        # Statuses worth reporting are handled by the inherited _skip analyser
        # (skips 0 and 404). These extra analysers flag likely admin interfaces.
        self._auth_status = StatusCodeAnalyser([401])
        self._auth_header = HeaderAnalyser("WWW-Authenticate")
        self._login_body = RegexAnalyser(
            r"(type=[\"']password[\"']|name=[\"']password[\"']|"
            r"<title>[^<]*(admin|login|sign\s*in)|"
            r"please\s+(log\s*in|sign\s*in))",
            flags=re.IGNORECASE,
        )

    def setup(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(prog="adminfinder", add_help=False)
        parser.add_argument(
            "--admin-wordlist", metavar="PATH", default=None,
            help="Replace the built-in admin path list with entries from this file "
                 "(one path per line)",
        )
        parser.add_argument(
            "--admin-extra", metavar="PATH", default=None,
            help="Append the paths in this file on top of the built-in admin list",
        )
        parsed, _ = parser.parse_known_args(args)

        if parsed.admin_wordlist:
            self._wordlist = self._read_paths(parsed.admin_wordlist)
        else:
            self._wordlist = list(self.DEFAULT_ADMIN_PATHS)

        if parsed.admin_extra:
            self._wordlist.extend(self._read_paths(parsed.admin_extra))

    @staticmethod
    def _read_paths(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip().lstrip("/") for line in f if line.strip()]

    async def mutate(self, requests, context):
        if not self._wordlist:
            raise RuntimeError(
                "adminfinder has no admin paths to test. Provide --admin-wordlist "
                "with a non-empty file, or omit it to use the built-in list."
            )
        return self._admin_variants(requests)

    def _admin_variants(self, requests):
        for req in requests:
            base = self._origin_request(req)
            yield from self._keyword_variants(base)

    def _origin_request(self, req):
        """
        Return a copy of req whose URL is the target origin with the keyword
        sentinel appended, so PathFuzzer._keyword_variants substitutes each
        admin path at the site root.
        """
        parsed = urlparse(req.url)
        root = urlunparse(parsed._replace(
            path=f"/{self._keyword}", params="", query="", fragment="",
        ))
        # url-only mutation, safe to alias the unmutated headers/params.
        return replace(req, url=root)

    async def analyze_one(self, response, context):
        if self._skip.matches(response):
            return
        flags = []
        if self._auth_status.matches(response) and self._auth_header.matches(response):
            flags.append("auth-challenge")
        if self._login_body.matches(response):
            flags.append("login-page")
        suffix = f"  [likely admin: {', '.join(flags)}]" if flags else ""
        print(
            f"[ADMINFINDER] {response.status} {response.request.method} "
            f"{response.request.url}{suffix}"
        )
