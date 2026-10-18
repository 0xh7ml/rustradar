//! `rustradar` command-line entry point.
//!
//! Steps: raise the open-file limit, parse flags (merging the flag config
//! file), configure logging, handle the informational flags (`-version`,
//! `-ls`, `-up` self-update), validate, build the [`Runner`], and run until done or Ctrl-C.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use rustradar::logger::{self, Level};
use rustradar::runner::{self, config, Options, Runner};
use rustradar::{error, fatal, warn, VERSION};

fn main() -> ExitCode {
    raise_fd_limit();
    let options = parse_options();

    let level = if options.silent {
        Level::Fatal
    } else if options.verbose {
        Level::Verbose
    } else {
        Level::Info
    };
    logger::init(
        level,
        !options.no_color && std::env::var_os("NO_COLOR").is_none(),
    );

    if options.version {
        // Printed even with -silent: the user asked for it.
        eprintln!("rustradar v{VERSION}");
        eprintln!("Config directory: {}", config::config_dir().display());
        return ExitCode::SUCCESS;
    }
    if options.list_sources {
        println!("{}", runner::list_sources(options.json));
        return ExitCode::SUCCESS;
    }
    if options.update {
        return self_update(options.proxy.as_deref());
    }

    let default_provider = config::default_provider_config_path();
    if let Err(err) = config::create_provider_config_template(&default_provider) {
        error!("Could not create provider config file: {err:#}");
    }

    runner::show_banner();
    if let Err(err) = runner::validate_options(&options) {
        fatal!("Program exiting: {err:#}");
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => fatal!("Could not start async runtime: {err}"),
    };

    let show_stats = options.stats;
    let check_updates = !options.silent && !options.disable_update_check;
    let proxy = options.proxy.clone();
    rt.block_on(async move {
        // Runs alongside enumeration so it never delays results.
        let update_check = check_updates.then(|| {
            tokio::spawn(async move {
                runner::update::report_version_status(proxy.as_deref()).await;
            })
        });

        let runner = match Runner::new(options) {
            Ok(r) => r,
            Err(err) => fatal!("Could not create runner: {err:#}"),
        };

        let outcome = tokio::select! {
            result = runner.run_enumeration() => result,
            _ = tokio::signal::ctrl_c() => {
                warn!("Interrupted, exiting");
                return ExitCode::from(130);
            }
        };

        if let Some(check) = update_check {
            check.abort();
        }
        if show_stats {
            logger::print(&runner::stats::render_statistics(&runner.statistics()));
        }

        match outcome {
            Ok(_) => ExitCode::SUCCESS,
            Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
            Err(err) => fatal!("Could not run enumeration: {err:#}"),
        }
    })
}

/// `-up`: replace this binary with the latest GitHub release.
fn self_update(proxy: Option<&str>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => fatal!("Could not start async runtime: {err}"),
    };
    match rt.block_on(runner::update::self_update(proxy)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("Could not update rustradar: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parse CLI flags. Values from the flag config file are inserted *before*
/// the user's flags so the command line wins.
fn parse_options() -> Options {
    let user_args = runner::normalize_args(std::env::args_os().skip(1));
    let config_path = runner::options::find_config_arg(&user_args);
    let explicit = config_path.is_some();
    let config_path = config_path.unwrap_or_else(config::default_config_path);

    let mut args = vec![std::ffi::OsString::from("rustradar")];
    if config_path.exists() {
        match config::flag_config_args(&config_path) {
            Ok(extra) => args.extend(extra),
            Err(err) => {
                eprintln!("[FTL] Could not read config: {err:#}");
                std::process::exit(1);
            }
        }
    } else if explicit {
        eprintln!("[FTL] Config file {} does not exist", config_path.display());
        std::process::exit(1);
    }
    args.extend(user_args);

    let mut options = Options::parse_from(args);
    options.stdin = !std::io::stdin().is_terminal();
    options
}

/// `true` when the error chain contains a broken pipe (e.g. `| head`).
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
}

/// Raise the soft open-file limit to the hard limit so hundreds of concurrent
/// sockets do not fail with "too many open files". Failures are ignored.
fn raise_fd_limit() {
    #[cfg(unix)]
    {
        let _ = rlimit::increase_nofile_limit(u64::MAX);
    }
}
