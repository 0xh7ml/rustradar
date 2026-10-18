# Disclaimer

rustradar is intended for authorized security testing, bug bounty programs
within their published scope, asset inventory of your own organization, and
research.

* Only enumerate domains you own or are explicitly authorized to assess.
* Passive enumeration queries third-party services. Respect their terms of
  service, rate limits and API quotas (`-rl`, `-rls`). Be especially gentle
  with free community services such as crt.sh.
* Active mode (`-nW`) sends DNS queries for every candidate to public
  resolvers.

The authors accept no liability for misuse of this tool. You are responsible
for your actions.
