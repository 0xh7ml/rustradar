//! Using rustradar as a library.
//!
//! Run with: `cargo run --example sdk -- hackerone.com`

use std::sync::{Arc, Mutex};

use rustradar::runner::{Options, Runner, SharedWriter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hackerone.com".to_string());

    // Logs go to stderr; keep them quiet for this example.
    rustradar::logger::init(rustradar::logger::Level::Warning, true);

    // Start from the CLI defaults and change what you need.
    let options = Options {
        sources: vec!["crtsh".into(), "hackertarget".into(), "shodanct".into()],
        timeout: 20,
        ..Default::default()
    };

    // 1) Single domain, results returned as data. The callback fires live as
    //    each unique subdomain is found.
    let runner = Runner::new(options.clone())?.with_result_callback(|entry| {
        eprintln!("[live] {} (via {})", entry.host, entry.source);
    });
    let results = runner.enumerate_single_domain(&domain).await?;
    println!("{} subdomains for {domain}:", results.len());
    for host in results.hosts() {
        let sources: Vec<&str> = results.sources[host].iter().map(String::as_str).collect();
        println!("  {host}  [{}]", sources.join(","));
    }

    // 2) Several domains in parallel, written to any `Write` sink.
    let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink: SharedWriter = buffer.clone();
    let runner = Runner::new(options)?;
    let total = runner
        .enumerate_domains(["hackerone.com", "bugcrowd.com"], vec![sink])
        .await?;
    println!(
        "\nbatch found {total} subdomains, {} bytes of output",
        buffer.lock().unwrap().len()
    );

    // Per-source statistics.
    for (source, stats) in runner.statistics() {
        println!(
            "  {source:<15} results={:<5} requests={:<3} errors={}",
            stats.results, stats.requests, stats.errors
        );
    }
    Ok(())
}
