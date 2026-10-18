# Sources

rustradar ships 54 passive sources. `rustradar -ls` prints the live list
(`*` = needs a key, `~` = not used by default); `rustradar -ls -oJ` prints it as
JSON.

* **Default**: used unless you pass `-s` or `-all`. Sources marked `-all` are
  slow or quota-hungry and run only with `-all` or when named in `-s`.
* **Recursive**: can enumerate subdomains of a subdomain (`-recursive` keeps
  only these).
* **Key**: *required* sources are skipped (and listed as skipped in `-stats`)
  until a key is configured. *Optional* sources work without a key; a key
  raises limits.

Keys go in `provider-config.yaml` under the source name, or in
`<SOURCE>_API_KEY` (see [CONFIGURATION.md](CONFIGURATION.md)). Each source's
implementation is `src/subscraping/sources/<name>.rs`; its file header
documents the endpoint and key format.

## Catalog

| # | Source | Provider | Default | Recursive | Key | Key format |
|---:|---|---|:---:|:---:|:---:|---|
| 1 | `alienvault` | [AlienVault OTX](https://otx.alienvault.com) | yes | yes | **required** | OTX API key |
| 2 | `anubis` | [AnubisDB](https://anubisdb.com) | yes | | — | |
| 3 | `bevigil` | [BeVigil](https://bevigil.com/osint-api) | yes | | **required** | API key |
| 4 | `bufferover` | [BufferOver](https://tls.bufferover.run) | yes | yes | **required** | API key |
| 5 | `builtwith` | [BuiltWith](https://api.builtwith.com) | yes | | **required** | API key |
| 6 | `c99` | [C99](https://api.c99.nl) | yes | | **required** | API key |
| 7 | `censys` | [Censys Platform](https://platform.censys.io) | yes | | **required** | `PAT` or `PAT:ORG_ID` |
| 8 | `certspotter` | [Cert Spotter](https://sslmate.com/certspotter/api/) | yes | yes | **required** | API token |
| 9 | `chaos` | [Chaos](https://chaos.projectdiscovery.io) | yes | | **required** | API key |
| 10 | `chinaz` | [Chinaz](https://data.chinaz.com) | yes | | **required** | API key |
| 11 | `commoncrawl` | [Common Crawl](https://index.commoncrawl.org) | `-all` | | — | |
| 12 | `crtname` | [crt.name](https://crt.name) | yes | | optional | Bearer token |
| 13 | `crtsh` | [crt.sh](https://crt.sh) | yes | yes | — | |
| 14 | `digitalyama` | [DigitalYama](https://digitalyama.com) | yes | | **required** | API key |
| 15 | `digitorus` | [Digitorus](https://certificatedetails.com) | yes | yes | — | |
| 16 | `dnsdb` | [DNSDB](https://www.domaintools.com/products/farsight-dnsdb/) | `-all` | yes | **required** | API key |
| 17 | `dnsdumpster` | [DNSDumpster](https://dnsdumpster.com/developer/) | yes | | **required** | API key |
| 18 | `dnsrepo` | [DNSRepo / DNS Archive](https://dnsarchive.net) | yes | | **required** | `token:apikey` |
| 19 | `domainsproject` | [Domains Project](https://domainsproject.org) | yes | | **required** | `username:password` |
| 20 | `driftnet` | [Driftnet](https://driftnet.io) | yes | yes | **required** | API token |
| 21 | `fofa` | [FOFA](https://fofa.info) | yes | | **required** | `email:key` |
| 22 | `fullhunt` | [FullHunt](https://fullhunt.io) | yes | | **required** | API key |
| 23 | `github` | [GitHub code search](https://docs.github.com/en/rest/search) | `-all` | | **required** | personal access token(s) |
| 24 | `hackertarget` | [HackerTarget](https://hackertarget.com/find-dns-host-records/) | yes | yes | optional | API key |
| 25 | `hudsonrock` | [Hudson Rock](https://www.hudsonrock.com/free-tools) | `-all` | | — | |
| 26 | `intelx` | [Intelligence X](https://intelx.io) | yes | | **required** | `host:key` (e.g. `2.intelx.io:KEY`, free tier `free.intelx.io:KEY`) |
| 27 | `leakix` | [LeakIX](https://leakix.net) | yes | yes | **required** | API key |
| 28 | `merklemap` | [Merklemap](https://www.merklemap.com) | `-all` | yes | **required** | API key |
| 29 | `netlas` | [Netlas](https://netlas.io) | `-all` | | **required** | API key |
| 30 | `onyphe` | [ONYPHE](https://www.onyphe.io) | yes | | **required** | API key |
| 31 | `profundis` | [Profundis](https://profundis.io) | yes | | **required** | API key |
| 32 | `pugrecon` | [PugRecon](https://pugrecon.com) | `-all` | | **required** | API token |
| 33 | `quake` | [360 Quake](https://quake.360.net) | yes | | **required** | API token |
| 34 | `rapiddns` | [RapidDNS](https://rapiddns.io) | `-all` | | — | |
| 35 | `reconeer` | [Reconeer](https://www.reconeer.com) | yes | | optional | API key |
| 36 | `redhuntlabs` | [RedHunt Labs](https://devportal.redhuntlabs.com) | yes | | **required** | `<endpoint URL>:<key>`, e.g. `https://reconapi.redhuntlabs.com/community/v1/domains/subdomains:KEY` |
| 37 | `robtex` | [Robtex](https://www.robtex.com) | yes | | **required** | Pro API key |
| 38 | `rsecloud` | [RSECloud](https://rsecloud.com) | yes | | **required** | API key |
| 39 | `scanmalware` | [ScanMalware](https://scanmalware.com) | yes | yes | — | |
| 40 | `securitytrails` | [SecurityTrails](https://securitytrails.com) | yes | yes | **required** | API key |
| 41 | `shodan` | [Shodan](https://www.shodan.io) | yes | | **required** | API key |
| 42 | `shodanct` | [Shodan CT](https://ctl.shodan.io) | yes | yes | — | |
| 43 | `sitedossier` | [SiteDossier](http://www.sitedossier.com) | `-all` | | — | |
| 44 | `subdomaincenter` | [Subdomain Center](https://www.subdomain.center) | yes | yes | optional | `KEY`, or `KEY:crawl` to request a fresh crawl |
| 45 | `submd` | [sub.md](https://sub.md) | yes | | optional | Bearer token |
| 46 | `thc` | [THC](https://ip.thc.org) | `-all` | | — | |
| 47 | `threatbook` | [ThreatBook](https://x.threatbook.com) | `-all` | | **required** | API key |
| 48 | `threatcrowd` | [ThreatCrowd](https://ci-www.threatcrowd.org) | `-all` | | — | |
| 49 | `urlscan` | [urlscan.io](https://urlscan.io) | yes | yes | **required** | API key |
| 50 | `virustotal` | [VirusTotal](https://www.virustotal.com) | yes | yes | **required** | API key |
| 51 | `waybackarchive` | [Wayback Machine](https://web.archive.org) | `-all` | | — | |
| 52 | `whoisxmlapi` | [WhoisXML API](https://subdomains.whoisxmlapi.com) | yes | | **required** | API key |
| 53 | `windvane` | [Windvane](https://windvane.lichoin.com) | yes | | **required** | API key |
| 54 | `zoomeyeapi` | [ZoomEye](https://www.zoomeye.ai) | `-all` | | **required** | `host:key`, e.g. `zoomeye.ai:KEY` |

Totals: 40 default, 17 usable without a key, 16 recursive.

## Built-in rate limits

Applied automatically; override with `-rls name=N/unit`.

| Source | Limit | | Source | Limit |
|---|---|---|---|---|
| `github` | 83/m | | `virustotal` | 4/m |
| `fullhunt` | 60/m | | `hackertarget` | 2/s |
| `pugrecon` | 10/s | | `waybackarchive` | 15/m |
| `securitytrails` | 2/s | | `whoisxmlapi` | 50/s |
| `shodan` | 1/s | | `sitedossier` | 8/m |
| `netlas` | 1/s | | `hudsonrock` | 5/s |
| `urlscan` | 1/s | | | |

## Notes on specific sources

* **crtsh** queries the public PostgreSQL replica `guest@crt.sh:5432/certwatch`
  first (needs outbound TCP 5432). Without `-all` the query stops at 10,000
  rows. If the database is unreachable or empty, it falls back to the JSON
  API. Build with `--no-default-features` to drop the PostgreSQL client.
* **github** scans the search result snippets and downloads each matching
  file from `raw.githubusercontent.com`. Configure several tokens to keep
  going when one hits the search rate limit.
* **robtex** looks up the domain's A/AAAA records, then every name on those
  IPs. Names outside the target are discarded by the runner.
* **intelx** starts a phonebook search and polls for results (up to 60 polls).
* **netlas** downloads at most 200 results (community tier limit).
* **virustotal** free keys allow 4 requests/minute and 500/day; HTTP 429 is
  reported as "quota exhausted".
* **digitorus**, **reconeer**: at the time of writing, these providers may
  answer 403/401 without a browser session or key. That is reported as a
  source warning and does not affect other sources.

## Sources from subfinder that are not included

* `gitlab`: present upstream but not in the plan's catalog. It can be added
  following [ADDING_A_SOURCE.md](ADDING_A_SOURCE.md).
* `reconcloud`, `riddler`, `threatminer`: quarantined upstream (behind bot
  protection or offline).
