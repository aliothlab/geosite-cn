import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request

# --- geosite (domains) ---
GEOSITE_URL = os.environ.get(
    "GEOSITE_URL",
    "https://static-file-global.353355.xyz/rules/cn-additional-list.txt",
)
GEOSITE_JSON = os.environ.get("GEOSITE_JSON", "rules/geosite-cn.json")
MIN_DOMAINS = int(os.environ.get("MIN_DOMAINS", "1000"))

# --- geoip (CIDR, v4 + v6, gaoyifan/china-operator-ip) ---
GEOIP_V4_URL = os.environ.get(
    "GEOIP_V4_URL",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
)
GEOIP_V6_URL = os.environ.get(
    "GEOIP_V6_URL",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
)
GEOIP_JSON = os.environ.get("GEOIP_JSON", "rules/geoip-cn.json")
MIN_V4 = int(os.environ.get("MIN_V4", "1000"))
MIN_V6 = int(os.environ.get("MIN_V6", "100"))

# --- dae (V2Ray-format geoip.dat / geosite.dat, consumed via ext:"file.dat:tag") ---
# geosite tags are conventionally lower-case (domain-list-community), geoip tags
# upper-case (v2fly/geoip); dae matches case-insensitively but we mirror the
# canonical files so any consumer works.
GEOSITE_DAT = os.environ.get("GEOSITE_DAT", "rules/geosite-cn.dat")
GEOIP_DAT = os.environ.get("GEOIP_DAT", "rules/geoip-cn.dat")
GEOSITE_TAG = os.environ.get("GEOSITE_TAG", "cn")
GEOIP_TAG = os.environ.get("GEOIP_TAG", "CN")

VERSION_CEILING = int(os.environ.get("VERSION_CEILING", "15"))
FALLBACK_VERSION = int(os.environ.get("FALLBACK_VERSION", "3"))


def fetch(url, retries=3):
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "geosite-cn-singbox/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "replace")
        except Exception as exc:
            last = exc
    raise SystemExit(f"failed to fetch {url}: {last}")


def detect_version():
    env = os.environ.get("RULESET_VERSION")
    if env:
        return int(env)
    sb = shutil.which("sing-box")
    if not sb:
        return FALLBACK_VERSION
    for v in range(VERSION_CEILING, 1, -1):
        src = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        src.write(json.dumps({"version": v, "rules": [{"domain_suffix": ["a.com"]}]}))
        src.close()
        out = src.name + ".srs"
        code = subprocess.run(
            [sb, "rule-set", "compile", "--output", out, src.name],
            capture_output=True,
        ).returncode
        os.unlink(src.name)
        if os.path.exists(out):
            os.unlink(out)
        if code == 0:
            return v
    return FALLBACK_VERSION


def parse_domains(text):
    seen = set()
    out = []
    for line in text.splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("+").lstrip(".")
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return out


def parse_cidrs(text):
    seen = set()
    nets = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.split()[0]
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        nets.append(net)
    return nets


def write_ruleset(path, ruleset):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")


# --- minimal V2Ray/Xray .dat (protobuf) encoder, no third-party deps ---
# Schema (v2fly/v2ray-core app/router/routercommon/common.proto):
#   CIDR        { bytes ip = 1; uint32 prefix = 2; }
#   GeoIP       { string country_code = 1; repeated CIDR cidr = 2; }
#   GeoIPList   { repeated GeoIP entry = 1; }              -> geoip.dat
#   Domain      { Type type = 1; string value = 2; }       Type: RootDomain = 2
#   GeoSite     { string country_code = 1; repeated Domain domain = 2; }
#   GeoSiteList { repeated GeoSite entry = 1; }            -> geosite.dat
# domain_suffix maps to Domain.Type RootDomain (matches the domain and subdomains).
ROOT_DOMAIN = 2  # Domain.Type.RootDomain


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _pb_varint(field, value):
    return _tag(field, 0) + _varint(value)


def _pb_bytes(field, data):
    return _tag(field, 2) + _varint(len(data)) + data


def _pb_string(field, s):
    return _pb_bytes(field, s.encode("utf-8"))


def encode_geosite_dat(tag, domains):
    site = _pb_string(1, tag)
    for d in domains:
        dom = _pb_varint(1, ROOT_DOMAIN) + _pb_string(2, d)
        site += _pb_bytes(2, dom)
    return _pb_bytes(1, site)  # GeoSiteList { entry }


def encode_geoip_dat(tag, cidrs):
    geo = _pb_string(1, tag)
    for ip_bytes, prefix in cidrs:
        cidr = _pb_bytes(1, ip_bytes) + _pb_varint(2, prefix)
        geo += _pb_bytes(2, cidr)
    return _pb_bytes(1, geo)  # GeoIPList { entry }


def write_dat(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def build_geosite(version):
    domains = parse_domains(fetch(GEOSITE_URL))
    if len(domains) < MIN_DOMAINS:
        raise SystemExit(f"only {len(domains)} domains parsed (< {MIN_DOMAINS})")
    write_ruleset(GEOSITE_JSON, {"version": version, "rules": [{"domain_suffix": domains}]})
    print(f"wrote {GEOSITE_JSON}: {len(domains)} domain_suffix (version {version})")
    write_dat(GEOSITE_DAT, encode_geosite_dat(GEOSITE_TAG, domains))
    print(f"wrote {GEOSITE_DAT}: {len(domains)} domains (dae, tag '{GEOSITE_TAG}')")


def build_geoip(version):
    v4 = parse_cidrs(fetch(GEOIP_V4_URL))
    v6 = parse_cidrs(fetch(GEOIP_V6_URL))
    if len(v4) < MIN_V4:
        raise SystemExit(f"only {len(v4)} IPv4 CIDRs parsed (< {MIN_V4})")
    if len(v6) < MIN_V6:
        raise SystemExit(f"only {len(v6)} IPv6 CIDRs parsed (< {MIN_V6})")
    allnets = sorted(v4 + v6, key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    cidrs = [str(n) for n in allnets]
    write_ruleset(GEOIP_JSON, {"version": version, "rules": [{"ip_cidr": cidrs}]})
    print(f"wrote {GEOIP_JSON}: {len(v4)} v4 + {len(v6)} v6 = {len(cidrs)} ip_cidr (version {version})")
    dat_cidrs = [(n.network_address.packed, n.prefixlen) for n in allnets]
    write_dat(GEOIP_DAT, encode_geoip_dat(GEOIP_TAG, dat_cidrs))
    print(f"wrote {GEOIP_DAT}: {len(dat_cidrs)} CIDRs (dae, tag '{GEOIP_TAG}')")


def main():
    version = detect_version()
    build_geosite(version)
    build_geoip(version)


if __name__ == "__main__":
    main()
