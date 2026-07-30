"""
core.py — subdomain discovery, DNS resolution, and CDN detection logic.
Kept separate from app.py so the scanning engine can be reused/tested
independently of the Flask web layer.
"""

import concurrent.futures
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from urllib.parse import urlparse

import dns.resolver
import requests

MAX_WORKERS = 30
HTTP_TIMEOUT = 4
SOURCE_TIMEOUT = 20
DNS_TIMEOUT = 3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_FILE = os.path.join(BASE_DIR, "wordlist.txt")
CLOUDFLARE_RANGES_CACHE = {"v4": [], "v6": [], "ts": 0}

UA = "Mozilla/5.0 (compatible; subpanel-scanner/1.0)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})

# Common prefixes/suffixes used to generate permutations from subdomains
# that were already discovered, to catch things like dev-api, api-v2, etc.
PERMUTATION_TOKENS = [
    "dev", "test", "staging", "stg", "uat", "qa", "prod", "preprod", "demo",
    "new", "old", "v1", "v2", "internal", "int", "backup", "bak", "beta",
    "alpha", "sandbox", "corp", "admin",
]

CDN_CNAME_SIGNATURES = [
    ("Cloudflare", ["cloudflare.net", "cloudflare.com"]),
    ("Akamai", ["akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgesuite.net", "edgekey.net"]),
    ("Fastly", ["fastly.net", "fastlylb.net"]),
    ("Amazon CloudFront", ["cloudfront.net"]),
    ("Amazon S3 / AWS", ["amazonaws.com"]),
    ("Google Cloud CDN", ["googleusercontent.com", "ghs.google.com", "1e100.net"]),
    ("Microsoft Azure CDN", ["azureedge.net", "azurefd.net", "trafficmanager.net"]),
    ("Sucuri", ["sucuri.net"]),
    ("Incapsula / Imperva", ["incapdns.net", "impervadns.net"]),
    ("StackPath", ["stackpathdns.com", "stackpathcdn.com"]),
    ("KeyCDN", ["kxcdn.com"]),
    ("BunnyCDN", ["b-cdn.net"]),
    ("CacheFly", ["cachefly.net"]),
    ("Netlify", ["netlify.app", "netlifyglobalcdn.com"]),
    ("Vercel", ["vercel-dns.com", "vercel.app"]),
    ("Tencent Cloud CDN", ["cdntip.com", "tencent-cloud.net"]),
    ("Alibaba Cloud CDN", ["kunlunca.com", "alikunlun.com", "aliyuncs.com"]),
    ("CDN77", ["cdn77.org"]),
    ("Limelight", ["llnwd.net", "edgecastcdn.net"]),
]

CDN_HEADER_SIGNATURES = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "cloudfront", "Amazon CloudFront"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("server", "fastly", "Fastly"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-iinfo", "", "Incapsula / Imperva"),
    ("server", "netlify", "Netlify"),
    ("x-vercel-id", "", "Vercel"),
    ("server", "tengine", "Alibaba Cloud (Tengine)"),
]

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "whm", "autodiscover", "autoconfig", "m", "mobile", "api", "dev", "staging",
    "test", "vpn", "portal", "admin", "cdn", "static", "img", "images", "cache",
    "app", "apps", "beta", "shop", "blog", "support", "help", "cloud", "gateway",
    "edge", "media", "assets", "download", "downloads", "secure", "login", "sso",
]


def load_wordlist():
    if os.path.isfile(WORDLIST_FILE):
        with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
            if words:
                return words
    return DEFAULT_WORDLIST


def save_wordlist(text):
    with open(WORDLIST_FILE, "w", encoding="utf-8") as f:
        f.write(text.strip() + "\n")


# -----------------------------------------------------------------------
# Passive sources — all free, no API key required.
# Each function returns a set of "sub.domain.tld" strings (lowercase,
# no leading '*.', guaranteed to end with the queried domain).
# -----------------------------------------------------------------------
def _clean(name, domain):
    name = (name or "").strip().lower().lstrip("*.")
    if name.endswith(domain) and re.match(r"^[a-z0-9_.-]+$", name):
        return name
    return None


def from_crtsh(domain):
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = SESSION.get(url, timeout=SOURCE_TIMEOUT)
        if r.status_code == 200 and r.text.strip():
            try:
                data = r.json()
            except json.JSONDecodeError:
                data = json.loads("[" + r.text.replace("}{", "},{") + "]")
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    cleaned = _clean(name, domain)
                    if cleaned:
                        found.add(cleaned)
    except Exception as e:
        print(f"[crt.sh] error: {e}")
    return found


def from_hackertarget(domain):
    found = set()
    try:
        r = SESSION.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain}, timeout=SOURCE_TIMEOUT,
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:40]:
            for line in r.text.splitlines():
                name = line.split(",")[0]
                cleaned = _clean(name, domain)
                if cleaned:
                    found.add(cleaned)
    except Exception as e:
        print(f"[hackertarget] error: {e}")
    return found


def from_rapiddns(domain):
    found = set()
    try:
        r = SESSION.get(
            f"https://rapiddns.io/subdomain/{domain}",
            params={"full": "1"}, timeout=SOURCE_TIMEOUT,
        )
        if r.status_code == 200:
            for name in re.findall(r"<td>([a-zA-Z0-9_.*-]+\." + re.escape(domain) + r")</td>", r.text):
                cleaned = _clean(name, domain)
                if cleaned:
                    found.add(cleaned)
    except Exception as e:
        print(f"[rapiddns] error: {e}")
    return found


def from_certspotter(domain):
    found = set()
    try:
        r = SESSION.get(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=SOURCE_TIMEOUT,
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("dns_names", []):
                    cleaned = _clean(name, domain)
                    if cleaned:
                        found.add(cleaned)
    except Exception as e:
        print(f"[certspotter] error: {e}")
    return found


def from_alienvault(domain):
    found = set()
    try:
        r = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=SOURCE_TIMEOUT,
        )
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                cleaned = _clean(entry.get("hostname", ""), domain)
                if cleaned:
                    found.add(cleaned)
    except Exception as e:
        print(f"[alienvault] error: {e}")
    return found


def from_anubis(domain):
    found = set()
    try:
        r = SESSION.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=SOURCE_TIMEOUT)
        if r.status_code == 200:
            for name in r.json():
                cleaned = _clean(name, domain)
                if cleaned:
                    found.add(cleaned)
    except Exception as e:
        print(f"[anubis] error: {e}")
    return found


def from_wayback(domain):
    found = set()
    try:
        r = SESSION.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "100000",
            },
            timeout=SOURCE_TIMEOUT,
        )
        if r.status_code == 200:
            rows = r.json()
            for row in (rows[1:] if rows else []):  # first row is the header
                try:
                    host = urlparse(row[0]).hostname or ""
                except Exception:
                    continue
                cleaned = _clean(host, domain)
                if cleaned:
                    found.add(cleaned)
    except Exception as e:
        print(f"[wayback] error: {e}")
    return found


def from_subfinder(domain):
    found = set()
    binary = shutil.which("subfinder")
    if not binary:
        return found
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        for line in proc.stdout.splitlines():
            cleaned = _clean(line, domain)
            if cleaned:
                found.add(cleaned)
    except Exception as e:
        print(f"[subfinder] error: {e}")
    return found


PASSIVE_SOURCES = [
    ("crt.sh", from_crtsh),
    ("HackerTarget", from_hackertarget),
    ("RapidDNS", from_rapiddns),
    ("CertSpotter", from_certspotter),
    ("AlienVault OTX", from_alienvault),
    ("Anubis/JLDC", from_anubis),
    ("Wayback Machine", from_wayback),
]


def gather_passive(domain):
    """Run every passive source concurrently, return (merged set, per-source counts)."""
    merged = set()
    counts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PASSIVE_SOURCES)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in PASSIVE_SOURCES}
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                found = fut.result()
            except Exception as e:
                found = set()
                print(f"[{name}] error: {e}")
            counts[name] = len(found)
            merged |= found
    return merged, counts


# -----------------------------------------------------------------------
# DNS / wildcard / brute-force
# -----------------------------------------------------------------------
def get_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def detect_wildcard(domain, resolver):
    """Query a random, near-certainly-nonexistent label. If it resolves,
    the zone has a DNS wildcard and brute-force/permutation results must be
    filtered against these IPs to avoid a flood of false positives."""
    label = f"nx-{secrets.token_hex(5)}"
    ips = resolve_a_records(f"{label}.{domain}", resolver)
    return set(ips)


def from_bruteforce(domain, resolver, wildcard_ips=None, words=None):
    found = set()
    wildcard_ips = wildcard_ips or set()
    words = words if words is not None else load_wordlist()

    def check(word):
        candidate = f"{word}.{domain}"
        try:
            answers = resolver.resolve(candidate, "A")
            ips = {str(r) for r in answers}
        except Exception:
            return None
        if wildcard_ips and ips and ips.issubset(wildcard_ips):
            return None
        return candidate

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for result in ex.map(check, words):
            if result:
                found.add(result)
    return found


def resolve_hosts(hosts, resolver, wildcard_ips=None):
    """Resolve a list of already-fully-qualified hostnames, dropping any
    that only match the wildcard IP set."""
    wildcard_ips = wildcard_ips or set()
    found = set()

    def check(host):
        try:
            answers = resolver.resolve(host, "A")
            ips = {str(r) for r in answers}
        except Exception:
            return None
        if wildcard_ips and ips and ips.issubset(wildcard_ips):
            return None
        return host

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for result in ex.map(check, hosts):
            if result:
                found.add(result)
    return found


def generate_permutations(known_subdomains, domain):
    """Build candidate hostnames like dev-api.domain / api-dev.domain from
    the first-level labels of subdomains already discovered."""
    labels = set()
    suffix = "." + domain
    for sd in known_subdomains:
        if not sd.endswith(suffix):
            continue
        prefix = sd[: -len(suffix)]
        first_label = prefix.split(".")[0] if prefix else ""
        if first_label and first_label not in PERMUTATION_TOKENS:
            labels.add(first_label)

    candidates = set()
    for label in labels:
        for token in PERMUTATION_TOKENS:
            candidates.add(f"{token}-{label}.{domain}")
            candidates.add(f"{label}-{token}.{domain}")
    return candidates


def refresh_cloudflare_ranges():
    now = time.time()
    if now - CLOUDFLARE_RANGES_CACHE["ts"] < 3600 and CLOUDFLARE_RANGES_CACHE["v4"]:
        return
    try:
        v4 = SESSION.get("https://www.cloudflare.com/ips-v4", timeout=5).text.split()
        v6 = SESSION.get("https://www.cloudflare.com/ips-v6", timeout=5).text.split()
        CLOUDFLARE_RANGES_CACHE["v4"] = [ipaddress.ip_network(c) for c in v4 if c]
        CLOUDFLARE_RANGES_CACHE["v6"] = [ipaddress.ip_network(c) for c in v6 if c]
        CLOUDFLARE_RANGES_CACHE["ts"] = now
    except Exception as e:
        print(f"[cloudflare ranges] error: {e}")


def ip_is_cloudflare(ip):
    refresh_cloudflare_ranges()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    ranges = CLOUDFLARE_RANGES_CACHE["v6"] if addr.version == 6 else CLOUDFLARE_RANGES_CACHE["v4"]
    return any(addr in net for net in ranges)


def resolve_cname_chain(hostname, resolver, max_hops=6):
    chain = []
    current = hostname
    for _ in range(max_hops):
        try:
            answer = resolver.resolve(current, "CNAME")
            target = str(answer[0].target).rstrip(".").lower()
            chain.append(target)
            current = target
        except Exception:
            break
    return chain


def resolve_a_records(hostname, resolver):
    ips = []
    try:
        answer = resolver.resolve(hostname, "A")
        ips = [str(r) for r in answer]
    except Exception:
        pass
    if not ips:
        try:
            answer = resolver.resolve(hostname, "AAAA")
            ips = [str(r) for r in answer]
        except Exception:
            pass
    return ips


def detect_cdn_from_cname(cname_chain):
    for cname in cname_chain:
        for cdn_name, signatures in CDN_CNAME_SIGNATURES:
            if any(sig in cname for sig in signatures):
                return cdn_name
    return None


def detect_cdn_from_headers(hostname):
    for scheme in ("https", "http"):
        try:
            r = SESSION.head(
                f"{scheme}://{hostname}", timeout=HTTP_TIMEOUT,
                allow_redirects=True,
            )
            headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            for header_name, value_substr, cdn_name in CDN_HEADER_SIGNATURES:
                if header_name in headers:
                    if value_substr == "" or value_substr in headers[header_name]:
                        return cdn_name
        except Exception:
            continue
    return None


def analyze_subdomain(hostname, resolver):
    cname_chain = resolve_cname_chain(hostname, resolver)
    ips = resolve_a_records(hostname, resolver)

    cdn = detect_cdn_from_cname(cname_chain)
    if not cdn:
        for ip in ips:
            if ip_is_cloudflare(ip):
                cdn = "Cloudflare"
                break
    if not cdn:
        cdn = detect_cdn_from_headers(hostname)

    return {
        "subdomain": hostname,
        "ip": ips if ips else [],
        "cname": cname_chain[-1] if cname_chain else None,
        "cdn": cdn or "Không phát hiện / Direct",
        "alive": bool(ips),
    }


def run_scan(domain, use_subfinder=True, use_brute=True, use_permutation=True):
    domain = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0]
    if not domain or "." not in domain:
        raise ValueError("Tên miền không hợp lệ")

    resolver = get_resolver()
    wildcard_ips = detect_wildcard(domain, resolver)

    # 1) All free passive sources (crt.sh, HackerTarget, RapidDNS, CertSpotter,
    #    AlienVault OTX, Anubis, Wayback Machine) run in parallel.
    subdomains, source_counts = gather_passive(domain)

    # 2) Optional local subfinder binary, if installed on the host.
    if use_subfinder:
        found = from_subfinder(domain)
        source_counts["subfinder"] = len(found)
        subdomains |= found

    # 3) Optional DNS brute-force with the user's wordlist.
    if use_brute:
        found = from_bruteforce(domain, resolver, wildcard_ips=wildcard_ips)
        source_counts["Brute-force wordlist"] = len(found)
        subdomains |= found

        # 4) Permutations built from names already found (dev-api, api-dev, ...)
        if use_permutation:
            perm_candidates = generate_permutations(subdomains, domain)
            perm_found = resolve_hosts(perm_candidates, resolver, wildcard_ips=wildcard_ips)
            source_counts["Permutation"] = len(perm_found)
            subdomains |= perm_found

    subdomains.add(domain)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(analyze_subdomain, sd, get_resolver()): sd for sd in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({
                    "subdomain": futures[fut], "ip": [], "cname": None,
                    "cdn": "Lỗi", "alive": False, "error": str(e)
                })

    results.sort(key=lambda r: (not r["alive"], r["subdomain"]))
    return {
        "domain": domain,
        "total": len(results),
        "alive": sum(1 for r in results if r["alive"]),
        "results": results,
        "has_wildcard": bool(wildcard_ips),
        "source_counts": source_counts,
    }
