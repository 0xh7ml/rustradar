//! The built-in passive sources.
//!
//! Each file implements one provider as a unit struct implementing
//! [`Source`]. To add a source:
//!
//! 1. Copy an existing file of the same shape (simple JSON GET: `anubis.rs`;
//!    keyed JSON: `fullhunt.rs`; paginated: `virustotal.rs`; text scraping:
//!    `hackertarget.rs`).
//! 2. Declare its metadata with `source_info!`.
//! 3. Add `mod <name>;` below and an entry in [`all`].
//! 4. Document it in `docs/SOURCES.md` (and add a default rate limit in
//!    `passive::DEFAULT_RATE_LIMITS` if the provider is strict).
//!
//! The full walkthrough is in `docs/ADDING_A_SOURCE.md`.

use std::sync::Arc;

use super::Source;

/// Declare the static `INFO` for a source file.
macro_rules! source_info {
    ($name:literal, default: $d:expr, recursive: $r:expr, key: $k:ident) => {
        static INFO: $crate::subscraping::SourceInfo = $crate::subscraping::SourceInfo {
            name: $name,
            is_default: $d,
            recursive: $r,
            key: $crate::subscraping::KeyRequirement::$k,
        };
    };
}

/// Imports shared by every source file.
#[allow(unused_imports)]
pub(crate) mod prelude {
    pub use crate::subscraping::session::status_of;
    pub use crate::subscraping::utils::{host_of, url_decode, url_encode};
    pub use crate::subscraping::{Ctx, Source, SourceInfo};
    pub use anyhow::{bail, Context as _, Result};
    pub use async_trait::async_trait;
    pub use serde::Deserialize;
    pub use serde_json::{json, Value};
}

mod alienvault;
mod anubis;
mod bevigil;
mod bufferover;
mod builtwith;
mod c99;
mod censys;
mod certspotter;
mod chaos;
mod chinaz;
mod commoncrawl;
mod crtname;
mod crtsh;
mod digitalyama;
mod digitorus;
mod dnsdb;
mod dnsdumpster;
mod dnsrepo;
mod domainsproject;
mod driftnet;
mod fofa;
mod fullhunt;
mod github;
mod hackertarget;
mod hudsonrock;
mod intelx;
mod leakix;
mod merklemap;
mod netlas;
mod onyphe;
mod profundis;
mod pugrecon;
mod quake;
mod rapiddns;
mod reconeer;
mod redhuntlabs;
mod robtex;
mod rsecloud;
mod scanmalware;
mod securitytrails;
mod shodan;
mod shodanct;
mod sitedossier;
mod subdomaincenter;
mod submd;
mod thc;
mod threatbook;
mod threatcrowd;
mod urlscan;
mod virustotal;
mod waybackarchive;
mod whoisxmlapi;
mod windvane;
mod zoomeyeapi;

/// Every built-in source, in alphabetical order.
pub fn all() -> Vec<Arc<dyn Source>> {
    vec![
        Arc::new(alienvault::AlienVault),
        Arc::new(anubis::Anubis),
        Arc::new(bevigil::Bevigil),
        Arc::new(bufferover::BufferOver),
        Arc::new(builtwith::BuiltWith),
        Arc::new(c99::C99),
        Arc::new(censys::Censys),
        Arc::new(certspotter::CertSpotter),
        Arc::new(chaos::Chaos),
        Arc::new(chinaz::Chinaz),
        Arc::new(commoncrawl::CommonCrawl),
        Arc::new(crtname::CrtName),
        Arc::new(crtsh::CrtSh),
        Arc::new(digitalyama::DigitalYama),
        Arc::new(digitorus::Digitorus),
        Arc::new(dnsdb::DnsDb),
        Arc::new(dnsdumpster::DnsDumpster),
        Arc::new(dnsrepo::DnsRepo),
        Arc::new(domainsproject::DomainsProject),
        Arc::new(driftnet::Driftnet),
        Arc::new(fofa::Fofa),
        Arc::new(fullhunt::FullHunt),
        Arc::new(github::GitHub),
        Arc::new(hackertarget::HackerTarget),
        Arc::new(hudsonrock::HudsonRock),
        Arc::new(intelx::IntelX),
        Arc::new(leakix::LeakIx),
        Arc::new(merklemap::MerkleMap),
        Arc::new(netlas::Netlas),
        Arc::new(onyphe::Onyphe),
        Arc::new(profundis::Profundis),
        Arc::new(pugrecon::PugRecon),
        Arc::new(quake::Quake),
        Arc::new(rapiddns::RapidDns),
        Arc::new(reconeer::Reconeer),
        Arc::new(redhuntlabs::RedHuntLabs),
        Arc::new(robtex::Robtex),
        Arc::new(rsecloud::RseCloud),
        Arc::new(scanmalware::ScanMalware),
        Arc::new(securitytrails::SecurityTrails),
        Arc::new(shodan::Shodan),
        Arc::new(shodanct::ShodanCt),
        Arc::new(sitedossier::SiteDossier),
        Arc::new(subdomaincenter::SubdomainCenter),
        Arc::new(submd::SubMd),
        Arc::new(thc::Thc),
        Arc::new(threatbook::ThreatBook),
        Arc::new(threatcrowd::ThreatCrowd),
        Arc::new(urlscan::UrlScan),
        Arc::new(virustotal::VirusTotal),
        Arc::new(waybackarchive::WaybackArchive),
        Arc::new(whoisxmlapi::WhoisXmlApi),
        Arc::new(windvane::Windvane),
        Arc::new(zoomeyeapi::ZoomEyeApi),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_has_54_unique_sorted_sources() {
        let sources = all();
        assert_eq!(sources.len(), 54);
        let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "duplicate source names");
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "keep all() alphabetical");
        assert!(names.iter().all(|n| n
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())));
    }

    #[test]
    fn default_rate_limits_reference_real_sources() {
        let names: HashSet<&str> = all().iter().map(|s| s.name()).collect();
        for entry in crate::passive::DEFAULT_RATE_LIMITS {
            let name = entry.split('=').next().unwrap();
            assert!(
                names.contains(name),
                "unknown source {name} in DEFAULT_RATE_LIMITS"
            );
        }
    }
}
