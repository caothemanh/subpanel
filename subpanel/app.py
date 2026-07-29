#!/usr/bin/env python3
"""
Subdomain Scanner Panel
------------------------
Web panel to enumerate subdomains of a domain, resolve their IPs,
and detect which CDN (if any) each one is fronted by.

Data sources for subdomain discovery:
  - crt.sh certificate transparency logs (no API key needed)
  - Optional: local tool "subfinder" if installed on the system (used automatically if found)
  - Optional: simple DNS wordlist brute force (small built-in list, extendable via wordlist.txt)

CDN detection heuristics:
  - CNAME chain pattern matching against known CDN hostname signatures
  - HTTP response headers (Server, X-Cache, CF-RAY, etc.) via a lightweight HEAD request
  - Known CDN IP ranges (Cloudflare) via their published CIDR list (fetched at startup, cached)

Run:
    pip3 install -r requirements.txt
    python3 app.py
Then open http://<server-ip>:5000
"""

import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time

import dns.resolver
import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------
MAX_WORKERS = 30
HTTP_TIMEOUT = 4
DNS_TIMEOUT = 3
WORDLIST_FILE = os.path.join(os.path.dirname(__file__), "wordlist.txt")
CLOUDFLARE_RANGES_CACHE = {"v4": [], "v6": [], "ts": 0}

# CNAME / hostname substrings that identify a CDN provider.
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

# HTTP header signatures (header_name -> (value_substring, CDN name))
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


# -----------------------------------------------------------------------
# Subdomain discovery
# -----------------------------------------------------------------------
def from_crtsh(domain):
    """Query crt.sh certificate transparency logs for subdomains."""
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200 and r.text.strip():
            try:
                data = r.json()
            except json.JSONDecodeError:
                # crt.sh sometimes returns concatenated JSON objects
                data = json.loads("[" + r.text.replace("}{", "},{") + "]")
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        found.add(name)
    except Exception as e:
        print(f"[crt.sh] error: {e}")
    return found


def from_subfinder(domain):
    """Use subfinder binary if installed on the host (optional, best results)."""
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
            line = line.strip().lower()
            if line.endswith(domain):
                found.add(line)
    except Exception as e:
        print(f"[subfinder] error: {e}")
    return found


def from_bruteforce(domain, resolver):
    """Small built-in DNS wordlist brute-force for common subdomain names."""
    found = set()
    words = load_wordlist()

    def check(word):
        candidate = f"{word}.{domain}"
        try:
            resolver.resolve(candidate, "A")
            return candidate
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for result in ex.map(check, words):
            if result:
                found.add(result)
    return found


# -----------------------------------------------------------------------
# DNS resolution + CDN detection
# -----------------------------------------------------------------------
def get_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def refresh_cloudflare_ranges():
    now = time.time()
    if now - CLOUDFLARE_RANGES_CACHE["ts"] < 3600 and CLOUDFLARE_RANGES_CACHE["v4"]:
        return
    try:
        v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=5).text.split()
        v6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=5).text.split()
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
            r = requests.head(
                f"{scheme}://{hostname}", timeout=HTTP_TIMEOUT,
                allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (subdomain-scanner)"}
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


# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip().lower()
    use_brute = bool(data.get("bruteforce", True))
    use_subfinder = bool(data.get("subfinder", True))

    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain or "." not in domain:
        return jsonify({"error": "Tên miền không hợp lệ"}), 400

    resolver = get_resolver()

    subdomains = set()
    subdomains |= from_crtsh(domain)
    if use_subfinder:
        subdomains |= from_subfinder(domain)
    if use_brute:
        subdomains |= from_bruteforce(domain, resolver)
    subdomains.add(domain)  # always include the apex domain itself

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
    return jsonify({
        "domain": domain,
        "total": len(results),
        "alive": sum(1 for r in results if r["alive"]),
        "results": results,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
