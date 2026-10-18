//! Startup banner and version information.

use crate::VERSION;

const BANNER: &str = r"
                __              __
  ______ _____ / /________ ____/ /__ _____
 / __/ // (_-</ __/ __/ _ `/ _  / _ `/ __/
/_/  \_,_/___/\__/_/  \_,_/\_,_/\_,_/_/
";

/// Print the banner to stderr (suppressed by `-silent`).
pub fn show_banner() {
    crate::logger::print(&format!("{BANNER}\n\t\trustradar v{VERSION}\n"));
    crate::logger::print("\t\tUse with caution. You are responsible for your actions.");
    crate::logger::print("\t\tOnly enumerate targets you are authorized to test.\n");
}
