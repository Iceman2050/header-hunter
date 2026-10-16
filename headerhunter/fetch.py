"""Respectful HTTP response-header fetcher.

One plain GET per URL, no JS execution, no credentials, capped redirects and
a short timeout. Returns the final response's headers plus fetch metadata.
"""

from __future__ import annotations

import urllib.error
import urllib.request

USER_AGENT = "header-hunter/1.0 (+https://github.com/ingeniousai/header-hunter)"
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 3


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block automatic redirect following so we can count them ourselves."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_once(url: str, timeout: int) -> tuple[dict, int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return headers, resp.status, resp.geturl()
    except urllib.error.HTTPError as e:
        # HTTPError still carries the response headers — keep them.
        headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return headers, e.code, url
    except Exception as e:  # network/DNS/TLS failure — report, don't crash
        return {}, 0, url


def fetch_headers(url: str, timeout: int = DEFAULT_TIMEOUT,
                  max_redirects: int = MAX_REDIRECTS) -> dict:
    """Fetch response headers for *url*.

    Follows at most *max_redirects* redirects manually (headers reported are
    from the FINAL response). Returns a dict with keys:
      url, final_url, status, redirects, headers (lowercased names), error.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    current = url
    redirects = 0
    while True:
        headers, status, final = _fetch_once(current, timeout)
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location")
            if loc and redirects < max_redirects:
                # resolve relative Location against the current URL
                current = urllib.request.urljoin(current, loc)
                redirects += 1
                continue
            if loc and redirects >= max_redirects:
                return {"url": url, "final_url": current, "status": status,
                        "redirects": redirects, "headers": headers,
                        "error": "redirect limit (%d) exceeded" % max_redirects}
        if status == 0:
            return {"url": url, "final_url": current, "status": 0,
                    "redirects": redirects, "headers": {},
                    "error": "request failed (network/DNS/TLS/timeout)"}
        return {"url": url, "final_url": final or current, "status": status,
                "redirects": redirects, "headers": headers, "error": ""}
