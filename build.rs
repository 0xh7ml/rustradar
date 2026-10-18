//! Record the target triple so the self-updater (`-up`) knows which release
//! archive to download.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=RUSTRADAR_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
