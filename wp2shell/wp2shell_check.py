#!/usr/bin/env python3
"""
wp2shell_check.py — Non-destructive checker for the WordPress Core
"batch-route confusion -> SQLi -> RCE" vulnerability (a.k.a. wp2shell).

Reported by Adam Kues (Assetnote / Searchlight Cyber). Fixed in WordPress
7.0.2 (and backported to 6.9.5). The vulnerable surface is the REST API
batch endpoint: /wp-json/batch/v1  (aka ?rest_route=/batch/v1).

Affected (for THIS RCE):
    6.9.0 - 6.9.4   -> vulnerable, fixed in 6.9.5
    7.0.0 - 7.0.1   -> vulnerable, fixed in 7.0.2
    7.1 beta1       -> vulnerable, fixed in 7.1 beta2
    < 6.9.0         -> not affected by the RCE
                       (6.8.x is affected by a *separate* SQLi fixed in 6.8.6)

WHAT THIS TOOL DOES (and does NOT do)
-------------------------------------
It is a DETECTION tool only. It:
  * fingerprints the WordPress version via several passive/standard endpoints,
  * checks whether the REST batch route is registered and whether it is
    reachable by an ANONYMOUS user (i.e. whether the recommended mitigation /
    the 7.0.2 fix appears to be in place),
  * combines those signals into a verdict.

It sends NO exploit payload, NO SQL injection, and NO batch operations that
change state. The batch probe uses OPTIONS / an empty request and only reads
the HTTP status and route metadata. It cannot compromise a site.

Only scan sites you own or are explicitly authorized to test.

Usage:
    python3 wp2shell_check.py https://example.com
    python3 wp2shell_check.py example.com another.com --json
    python3 wp2shell_check.py https://example.com --insecure --timeout 15
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Optional

USER_AGENT = "wp2shell-check/1.0 (+non-destructive WordPress version/batch-route checker)"

# --- Version ranges for the RCE ------------------------------------------------
# (low_inclusive, high_inclusive, fixed_in) tuples using version tuples.
AFFECTED_RANGES = [
    ((6, 9, 0), (6, 9, 4), "6.9.5"),
    ((7, 0, 0), (7, 0, 1), "7.0.2"),
]
# First version that is unaffected on each branch is the "fixed_in" above.
NOT_AFFECTED_BELOW = (6, 9, 0)  # for the RCE specifically


# ------------------------------------------------------------------------------
# Version parsing / comparison
# ------------------------------------------------------------------------------
_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str) -> Optional[tuple[int, int, int]]:
    """Extract the first x.y[.z] version-looking token. Returns (x,y,z) or None."""
    if not text:
        return None
    m = _VER_RE.search(text)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    return (major, minor, patch)


def is_beta_71(text: str) -> bool:
    """Detect the 7.1 beta1 pre-release which was also affected."""
    if not text:
        return False
    t = text.lower()
    return "7.1-beta1" in t or "7.1 beta 1" in t or bool(
        re.search(r"7\.1[-\s]?beta1\b", t)
    )


def classify_version(ver: tuple[int, int, int]) -> tuple[str, Optional[str]]:
    """
    Return (status, fixed_in) where status is one of:
      'vulnerable', 'not_affected'.
    """
    for low, high, fixed in AFFECTED_RANGES:
        if low <= ver <= high:
            return "vulnerable", fixed
    # Anything at or above a branch's fix, or below the affected floor.
    if ver < NOT_AFFECTED_BELOW:
        return "not_affected", None
    # >= 6.9.5 within 6.9, or >= 7.0.2, or 7.1+ release, etc.
    return "not_affected", None


# ------------------------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------------------------
@dataclass
class HttpResult:
    ok: bool
    status: Optional[int] = None
    body: str = ""
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None


def _make_opener(insecure: bool) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler)
    return opener


def http_request(
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
    insecure: bool = False,
    data: Optional[bytes] = None,
    extra_headers: Optional[dict] = None,
    max_bytes: int = 300_000,
) -> HttpResult:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    opener = _make_opener(insecure)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes)
            body = raw.decode("utf-8", errors="replace")
            return HttpResult(
                ok=True,
                status=resp.status,
                body=body,
                headers={k.lower(): v for k, v in resp.headers.items()},
            )
    except urllib.error.HTTPError as e:
        # HTTP errors (401/403/404/500...) are useful signals, not failures.
        raw = b""
        try:
            raw = e.read(max_bytes)
        except Exception:
            pass
        return HttpResult(
            ok=True,
            status=e.code,
            body=raw.decode("utf-8", errors="replace"),
            headers={k.lower(): v for k, v in (e.headers or {}).items()},
        )
    except urllib.error.URLError as e:
        return HttpResult(ok=False, error=str(e.reason))
    except Exception as e:  # timeouts, ssl errors, etc.
        return HttpResult(ok=False, error=str(e))


def normalize_base(target: str) -> str:
    target = target.strip().rstrip("/")
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target


# ------------------------------------------------------------------------------
# Version detection strategies (passive / standard endpoints)
# ------------------------------------------------------------------------------
def detect_version(base: str, timeout: float, insecure: bool, verbose: bool):
    """
    Try multiple standard sources. Returns (version_tuple, source, raw_string,
    saw_71_beta1). Any source that yields a plausible core version wins; we
    prefer the most authoritative ordering.
    """
    findings = []

    def note(src, raw):
        if verbose:
            print(f"    [version] {src}: {raw!r}", file=sys.stderr)

    # 1) Homepage <meta name="generator" content="WordPress X.Y.Z">
    r = http_request(base + "/", timeout=timeout, insecure=insecure)
    if r.ok and r.body:
        m = re.search(
            r'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']?WordPress\s*([^"\'>]+)',
            r.body, re.I,
        )
        if m:
            raw = "WordPress " + m.group(1).strip()
            note("homepage meta generator", raw)
            findings.append(("meta generator (homepage)", raw))

    # 2) RSS feed generator: <generator>https://wordpress.org/?v=X.Y.Z</generator>
    for feed in ("/feed/", "/?feed=rss2"):
        r = http_request(base + feed, timeout=timeout, insecure=insecure)
        if r.ok and r.body:
            m = re.search(r"wordpress\.org/\?v=([0-9][0-9.\-a-zA-Z]*)", r.body, re.I)
            if not m:
                m = re.search(r"<generator>[^<]*\?v=([0-9][0-9.\-a-zA-Z]*)", r.body, re.I)
            if m:
                raw = m.group(1).strip()
                note(f"RSS feed {feed}", raw)
                findings.append((f"RSS feed generator ({feed})", raw))
                break

    # 3) OPML: /wp-links-opml.php  (generator="WordPress/X.Y.Z")
    r = http_request(base + "/wp-links-opml.php", timeout=timeout, insecure=insecure)
    if r.ok and r.body:
        m = re.search(r'generator=["\']?WordPress/([0-9][0-9.\-a-zA-Z]*)', r.body, re.I)
        if m:
            raw = m.group(1).strip()
            note("wp-links-opml.php", raw)
            findings.append(("OPML generator", raw))

    # 4) readme.html  (often shows "Version X.Y.Z")
    r = http_request(base + "/readme.html", timeout=timeout, insecure=insecure)
    if r.ok and r.status == 200 and r.body:
        m = re.search(r"[Vv]ersion\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r.body)
        if m:
            raw = m.group(1).strip()
            note("readme.html", raw)
            findings.append(("readme.html", raw))

    # Pick the first finding that parses; collect 7.1-beta1 detection across all.
    saw_71_beta1 = any(is_beta_71(raw) for _, raw in findings)
    for source, raw in findings:
        ver = parse_version(raw)
        if ver:
            return ver, source, raw, saw_71_beta1
    return None, None, None, saw_71_beta1


# ------------------------------------------------------------------------------
# Batch-route probe (non-destructive)
# ------------------------------------------------------------------------------
def probe_batch_route(base: str, timeout: float, insecure: bool, verbose: bool):
    """
    Determine (a) whether the /batch/v1 route is registered, and (b) whether an
    anonymous request to it is blocked (401/403) or allowed through.

    Sends only OPTIONS and an EMPTY-body POST. No batch operations, no payloads.

    Returns a dict with keys: route_present, anon_blocked, detail, status_get,
    status_options, status_post.
    """
    result = {
        "route_present": None,     # True/False/None(unknown)
        "anon_blocked": None,      # True (mitigated/fixed) / False (reachable) / None
        "rest_reachable": None,
        "detail": "",
        "statuses": {},
    }

    # 0) Is the REST API reachable at all, and does the index list batch/v1?
    idx = http_request(base + "/wp-json/", timeout=timeout, insecure=insecure)
    if idx.ok:
        result["rest_reachable"] = idx.status == 200
        result["statuses"]["wp-json_index"] = idx.status
        if idx.status == 200 and idx.body:
            # The REST index enumerates registered routes.
            if re.search(r'/batch/v1', idx.body):
                result["route_present"] = True
            else:
                # Index present but batch route not listed -> likely not registered/exposed.
                result["route_present"] = False
    else:
        result["detail"] = f"REST index unreachable: {idx.error}"

    # 1) OPTIONS on the batch route: registered routes answer OPTIONS with an
    #    'Allow' header / schema. 404 -> not registered. 401/403 -> registered but gated.
    for probe_url in (base + "/wp-json/batch/v1",
                      base + "/?rest_route=/batch/v1"):
        opt = http_request(probe_url, method="OPTIONS", timeout=timeout, insecure=insecure)
        if not opt.ok:
            continue
        key = "OPTIONS " + ("wp-json" if "wp-json" in probe_url else "rest_route")
        result["statuses"][key] = opt.status
        if verbose:
            print(f"    [batch] {key} -> {opt.status}", file=sys.stderr)

        if opt.status == 404:
            # Route not found on this variant.
            if result["route_present"] is None:
                result["route_present"] = False
            continue

        # Any non-404 means the route exists on this path.
        result["route_present"] = True

        # 2) Empty POST to see how anonymous access is handled. An empty body
        #    triggers validation only; it performs no batch work.
        post = http_request(
            probe_url, method="POST", timeout=timeout, insecure=insecure,
            data=b"{}", extra_headers={"Content-Type": "application/json"},
        )
        pkey = "POST " + ("wp-json" if "wp-json" in probe_url else "rest_route")
        if post.ok:
            result["statuses"][pkey] = post.status
            if verbose:
                print(f"    [batch] {pkey} -> {post.status}", file=sys.stderr)

            code = ""
            try:
                j = json.loads(post.body)
                code = str(j.get("code", ""))
            except Exception:
                pass

            if post.status in (401, 403) or "authentication" in (code + post.body).lower() \
               and "rest_batch_authentication_required" in post.body:
                result["anon_blocked"] = True
                result["detail"] = (
                    "Anonymous request to the batch route is rejected "
                    f"(HTTP {post.status}) — the fix or a mitigation appears active."
                )
            elif post.status in (401, 403):
                result["anon_blocked"] = True
                result["detail"] = (
                    f"Anonymous batch request blocked (HTTP {post.status})."
                )
            else:
                # Reachable by anonymous user (e.g. 200/400 for bad body but processed).
                result["anon_blocked"] = False
                result["detail"] = (
                    f"Batch route is reachable by an anonymous user "
                    f"(HTTP {post.status}); not obviously gated."
                )
        break  # one working variant is enough

    if result["route_present"] is False and not result["detail"]:
        result["detail"] = "Batch route not registered / not exposed."
    return result


# ------------------------------------------------------------------------------
# Verdict
# ------------------------------------------------------------------------------
def build_verdict(version_status, fixed_in, saw_71_beta1, batch):
    """
    Combine version + batch-route signals into a single verdict string and
    a machine label: 'VULNERABLE' | 'LIKELY_PATCHED' | 'INDETERMINATE'.
    """
    reasons = []

    # 7.1 beta1 special case.
    if saw_71_beta1:
        return (
            "VULNERABLE",
            "Running WordPress 7.1 beta1, which is affected. Update to 7.1 beta2 "
            "or a stable fixed release (7.0.2+).",
        )

    if version_status == "vulnerable":
        reasons.append(
            f"Detected WordPress version falls in an affected range; fixed in {fixed_in}."
        )
        # Even if version is vulnerable, a mitigation may gate the route.
        if batch.get("anon_blocked") is True:
            return (
                "INDETERMINATE",
                "Version looks affected, BUT anonymous access to the batch route "
                "appears blocked — a mitigation (WAF / disable-batch plugin) may be "
                "active. Update to the fixed release to be certain. "
                + " ".join(reasons),
            )
        return ("VULNERABLE", " ".join(reasons) +
                " Anonymous access to the batch route was not observed to be blocked.")

    if version_status == "not_affected":
        # Version says patched. Cross-check with route behavior for confidence.
        if batch.get("anon_blocked") is False:
            return (
                "LIKELY_PATCHED",
                "Detected version is not in an affected range, though the batch "
                "route is still reachable anonymously (normal for a patched site — "
                "the fix corrects the route handling, it does not remove the route).",
            )
        return ("LIKELY_PATCHED",
                "Detected version is not in an affected range for this RCE.")

    # Version unknown — fall back to route signal only.
    if batch.get("anon_blocked") is True:
        return (
            "INDETERMINATE",
            "Could not read the WordPress version, but anonymous access to the "
            "batch route appears blocked (a mitigation may be active). Confirm the "
            "version manually and ensure you are on 7.0.2+/6.9.5+.",
        )
    if batch.get("route_present") is False:
        return (
            "INDETERMINATE",
            "Could not read the WordPress version and the batch route was not "
            "found. This may be a non-WordPress site, a hardened install, or the "
            "REST API is disabled. Verify the version manually.",
        )
    if batch.get("anon_blocked") is False:
        return (
            "INDETERMINATE",
            "Could not read the WordPress version, and the batch route is reachable "
            "anonymously. Cannot confirm exploitability non-destructively — check "
            "the version manually and update to 7.0.2+/6.9.5+ if affected.",
        )
    return ("INDETERMINATE",
            "Not enough signal to determine status. Verify the version manually.")


# ------------------------------------------------------------------------------
# Per-target scan
# ------------------------------------------------------------------------------
def scan_target(target: str, timeout: float, insecure: bool, verbose: bool) -> dict:
    base = normalize_base(target)
    out = {"target": target, "base_url": base}

    ver, source, raw, saw_71_beta1 = detect_version(base, timeout, insecure, verbose)
    if ver:
        status, fixed_in = classify_version(ver)
        out["version"] = ".".join(map(str, ver))
        out["version_source"] = source
        out["version_status"] = status
        out["fixed_in"] = fixed_in
    else:
        status, fixed_in = "unknown", None
        out["version"] = None
        out["version_source"] = None
        out["version_status"] = "unknown"
        out["fixed_in"] = None
    out["saw_71_beta1"] = saw_71_beta1

    batch = probe_batch_route(base, timeout, insecure, verbose)
    out["batch_probe"] = batch

    label, explanation = build_verdict(status, fixed_in, saw_71_beta1, batch)
    out["verdict"] = label
    out["explanation"] = explanation
    return out


# ------------------------------------------------------------------------------
# Output formatting
# ------------------------------------------------------------------------------
COLORS = {
    "VULNERABLE": "\033[97;41m",       # white on red
    "LIKELY_PATCHED": "\033[30;42m",   # black on green
    "INDETERMINATE": "\033[30;43m",    # black on yellow
    "reset": "\033[0m",
}


def print_human(res: dict, use_color: bool):
    def c(label):
        if not use_color:
            return label
        return f"{COLORS.get(label, '')}{label}{COLORS['reset']}"

    print(f"\n=== {res['base_url']} ===")
    v = res.get("version")
    print(f"  WordPress version : {v if v else 'unknown'}"
          + (f"  (via {res['version_source']})" if res.get("version_source") else ""))
    if res.get("fixed_in"):
        print(f"  Fixed in          : {res['fixed_in']}")
    b = res.get("batch_probe", {})
    rp = b.get("route_present")
    ab = b.get("anon_blocked")
    print(f"  Batch route       : "
          + ("present" if rp is True else "not found" if rp is False else "unknown"))
    print(f"  Anon access       : "
          + ("blocked (good)" if ab is True else "reachable" if ab is False else "unknown"))
    if b.get("statuses"):
        st = ", ".join(f"{k}={v}" for k, v in b["statuses"].items())
        print(f"  HTTP signals      : {st}")
    print(f"  VERDICT           : {c(res['verdict'])}")
    print(f"  {res['explanation']}")


REMEDIATION = """
Remediation (from WordPress.org / Searchlight Cyber):
  * Update WordPress immediately: 7.0.2 (or 6.9.5 on the 6.9 branch). Core
    auto-updates were force-enabled for affected versions.
  Temporary mitigations until you can update:
    - Install the "Disable WP REST API" plugin to block unauthenticated REST use.
    - At your WAF, block BOTH  /wp-json/batch/v1  AND  rest_route=/batch/v1
    - Or drop a small must-use/plugin that rejects anonymous /batch/v1 requests
      via the rest_pre_dispatch filter (see the advisory for the snippet).
"""


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Non-destructive checker for the WordPress batch-route RCE (wp2shell / fixed in 7.0.2).",
        epilog="Only scan sites you own or are authorized to test.",
    )
    p.add_argument("targets", nargs="+", help="One or more site URLs or hostnames.")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s). Default 10.")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--verbose", action="store_true", help="Print probe details to stderr.")
    args = p.parse_args(argv)

    use_color = (not args.no_color) and sys.stdout.isatty()

    results = []
    for t in args.targets:
        try:
            results.append(scan_target(t, args.timeout, args.insecure, args.verbose))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            results.append({"target": t, "verdict": "ERROR", "explanation": str(e)})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if r.get("verdict") == "ERROR":
                print(f"\n=== {r['target']} ===\n  ERROR: {r['explanation']}")
            else:
                print_human(r, use_color)
        print(REMEDIATION)

    # Exit code: 2 if any target is VULNERABLE, 1 if any INDETERMINATE/ERROR, else 0.
    labels = {r.get("verdict") for r in results}
    if "VULNERABLE" in labels:
        return 2
    if labels & {"INDETERMINATE", "ERROR"}:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
