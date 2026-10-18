//! Active DNS resolution and wildcard elimination (`-nW` / `-active`).
//!
//! * [`Resolver`] wraps an async DNS client (hickory) configured with public
//!   or user-supplied resolvers, with an optional shared concurrency limit.
//! * [`ResolutionPool`] detects wildcard DNS with random "canary" names, then
//!   resolves every candidate and drops those that point at wildcard IPs.

mod client;
mod pool;

pub use client::{Resolver, DEFAULT_RESOLVERS};
pub use pool::{HostEntry, ResolutionPool, ResolveResult, Resolved};
