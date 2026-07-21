# CN rule-sets for sing-box & dae

Mainland-China rule-sets, rebuilt daily via GitHub Actions. Three formats from one
source, so the domain/IP lists stay identical across them:

- **sing-box** `.json` + `.srs` — `version` auto-detected from the **latest sing-box
  prerelease** (alpha/beta), so it always tracks the newest rule-set format that
  prerelease supports.
- **dae** `.dat` — V2Ray/Xray-format `geoip.dat` / `geosite.dat`, loaded via `ext:`.

| Rule-set | Type | Source |
| --- | --- | --- |
| `geosite-cn` | `domain_suffix` | mainland-China ICP 备案 domain list |
| `geoip-cn` | `ip_cidr` (IPv4 **+** IPv6) | [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) (BGP, by-operator) |

Both are meant to be routed to **direct**.

## Files

| File | Format | Consumer | Tag inside |
| --- | --- | --- | --- |
| `rules/geosite-cn.json` | sing-box source | sing-box | — |
| `rules/geosite-cn.srs` | sing-box binary | sing-box | — |
| `rules/geosite-cn.dat` | V2Ray `geosite` | **dae** | `cn` |
| `rules/geoip-cn.json` | sing-box source | sing-box | — |
| `rules/geoip-cn.srs` | sing-box binary | sing-box | — |
| `rules/geoip-cn.dat` | V2Ray `geoip` | **dae** | `CN` |

- `geosite-cn` — CN domains, as `domain_suffix` (sing-box) / `RootDomain` (dae dat).
- `geoip-cn` — CN IPs, IPv4 **+** IPv6 combined in one set.

The `.dat` files each contain a single category (`cn` / `CN`); they are **not**
drop-in replacements for the full `geoip.dat` / `geosite.dat`, so keep the custom
names and reference them with `ext:` (below).

## Usage — sing-box

Example for a current sing-box (≥ 1.14, matching the prerelease this repo builds against).
`http_client.detour` replaces the deprecated `download_detour`, and the route rule uses the
explicit `action: "route"`:

```jsonc
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geosite-cn",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/aliothlab/rule-set/main/rules/geosite-cn.srs",
        "http_client": { "detour": "proxy" },
        "update_interval": "1d"
      },
      {
        "type": "remote",
        "tag": "geoip-cn",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/aliothlab/rule-set/main/rules/geoip-cn.srs",
        "http_client": { "detour": "proxy" },
        "update_interval": "1d"
      }
    ],
    "rules": [
      { "rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "direct" }
    ]
  }
}
```

> On older sing-box (< 1.14) use `"download_detour": "proxy"` instead of `http_client`.

## Usage — dae

[dae](https://github.com/daeuniverse/dae) reads V2Ray-format `geoip.dat` / `geosite.dat`
from its asset directory (default `/usr/local/share/dae/`) and can load extra dat files
by name with the `ext:"<file>:<tag>"` matcher. dae does **not** auto-update these — refresh
them yourself (e.g. a cron job) since this repo rebuilds daily.

```bash
# put the two custom dat files alongside dae's assets
sudo mkdir -p /usr/local/share/dae
base=https://raw.githubusercontent.com/aliothlab/rule-set/main/rules
sudo curl -fsSL "$base/geosite-cn.dat" -o /usr/local/share/dae/geosite-cn.dat
sudo curl -fsSL "$base/geoip-cn.dat"   -o /usr/local/share/dae/geoip-cn.dat
```

Then route the CN category to direct in `config.dae`:

```
routing {
    # CN domains and CN IPs -> direct
    domain(ext:"geosite-cn.dat:cn") -> direct
    dip(ext:"geoip-cn.dat:CN") -> direct

    fallback: proxy
}
```

Tags are matched case-insensitively, so `:cn` also works for geoip; the table above
lists the canonical tag baked into each file.

## Build

```bash
python3 build.py    # writes .json (sing-box) and .dat (dae) for both sets
sing-box rule-set compile --output rules/geosite-cn.srs rules/geosite-cn.json
sing-box rule-set compile --output rules/geoip-cn.srs   rules/geoip-cn.json
```

Rebuilt daily at 20:30 UTC (04:30 Asia/Shanghai); all six files are committed to the repo.
`build.py` needs no third-party packages — the `.dat` protobuf is encoded in pure Python.
