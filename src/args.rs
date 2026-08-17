//! CLI argument parsing — modeled on RustHound-CE's args.rs style.
//! ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/args.rs

use clap::{Arg, ArgAction, Command, value_parser};

// Tool version (pulled from Cargo.toml at compile time)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Collection methods
/// Which RPC interfaces to invoke.
#[derive(Clone, Debug)]
pub enum CollectionMethod {
    /// All three methods (SRVSVC + WKSSVC + WINREG). Default.
    All,
    /// Only SRVSVC / NetrSessionEnum (no admin needed on unpatched hosts).
    SessionOnly,
    /// Only WKSSVC / NetrWkstaUserEnum (admin on target required).
    LogonOnly,
    /// Only Remote Registry / HKEY_USERS (Remote Registry service required).
    RegistryOnly,
}

impl CollectionMethod {
    pub fn srvsvc(&self) -> bool {
        matches!(self, Self::All | Self::SessionOnly)
    }
    pub fn wkssvc(&self) -> bool {
        matches!(self, Self::All | Self::LogonOnly)
    }
    pub fn registry(&self) -> bool {
        matches!(self, Self::All | Self::RegistryOnly)
    }
}

// Output format

#[derive(Clone, Debug)]
pub enum OutputFormat {
    /// Pretty-printed JSON (default).
    Pretty,
    /// Compact JSON (one line).
    Compact,
}

// Options struct

/// All runtime options, built by [`extract_args`].
#[derive(Clone, Debug)]
pub struct Options {
    // Authentication
    /// NetBIOS domain name (e.g. CORP).
    pub domain: String,
    /// Username for SMB auth (e.g. alice or CORP\alice).
    pub username: String,
    /// Password for SMB auth (empty when --hashes is used).
    pub password: String,
    /// Parsed 16-byte NT hash for pass-the-hash — None when --password is used.
    /// Accepts NTHASH | :NTHASH | LMHASH:NTHASH (mirrors RustHound-CE).
    pub nt_hash: Option<[u8; 16]>,

    // Targets
    /// List of hosts to scan (from -t and/or --targets-file).
    pub targets: Vec<String>,

    // Collection
    /// Which RPC methods to run.
    pub collection_method: CollectionMethod,
    /// TCP connection timeout in seconds.
    pub timeout: u64,

    // Output
    /// JSON output format (pretty / compact).
    pub format: OutputFormat,
    /// Write JSON to this file instead of stdout (None = stdout).
    pub output: Option<String>,

    // Logging
    /// Verbosity: 0 = INFO / 1 = DEBUG / 2+ = TRACE.
    pub verbose: log::LevelFilter,
    /// Silence all [DEBUG] traces (same as -q / --quiet).
    pub quiet: bool,
}

// CLI definition

fn cli() -> Command {
    Command::new("HasSession-rs")
        .version(VERSION)
        .about(format!(
            "Enumerate logged-on users across Windows hosts via RPC, \
             and correlate them into a HasSession-like JSON report.\n\
             Built on icedracon's pure-Rust DCE/RPC stack (dcerpc + smb2-client).",
        ))
        .override_usage(
            "HasSession-rs -d <DOMAIN> -u <USER> (-p <PASS> | -H <HASH>) -t <HOST[,HOST]> [OPTIONS]"
        )
        .author("")

        // Required
        .next_help_heading("REQUIRED VALUES")
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .help("NetBIOS domain name (e.g. CORP or CORP.LOCAL)")
                .long_help(
                    "NetBIOS domain name used for NTLMv2 authentication.\n\
                     Examples: CORP  |  CORP.LOCAL\n\
                     Tip: use the short form (CORP), the DC will normalise it."
                )
                .required(true)
                .value_name("DOMAIN")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("username")
                .short('u')
                .long("username")
                .help("Username for SMB / RPC authentication")
                .long_help(
                    "Account used for NTLMv2 SMB session setup.\n\
                     Formats accepted: alice  |  CORP\\alice  |  alice@corp.local\n\
                     A low-privilege account is enough for SRVSVC on unpatched hosts;\n\
                     WKSSVC and Remote Registry usually require local admin."
                )
                .required(true)
                .value_name("USER")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .help("Password for SMB / RPC authentication (use -H for pass-the-hash)")
                .long_help(
                    "Plaintext password — used only to compute the NTLMv2 response;\n\
                     it never transits the network in cleartext.\n\
                     Tip: wrap in single quotes to avoid shell expansion: 'P@ssw0rd!'\n\
                     Mutually exclusive with --hashes (-H)."
                )
                .required(false)
                .value_name("PASS")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("hashes")
                .short('H')
                .long("hashes")
                .help("NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]")
                .long_help(
                    "Authenticate with the raw NT hash — no plaintext password needed.\n\
                     The hash is plugged directly into the NTLMv2 authenticate_hash() step.\n\n\
                     Accepted formats (mirrors RustHound-CE):\n  \
                       NTHASH                  — 32 hex chars, e.g. aad3b435b51404ee...\n  \
                       :NTHASH                 — colon prefix, LM part empty\n  \
                       LMHASH:NTHASH           — full pair, LM part is ignored\n\n\
                     Example: -H aad3b435b51404eeaad3b435b51404ee\n\
                     Example: -H :31d6cfe0d16ae931b73c59d7e0c089c0\n\
                     ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/ldap.rs"
                )
                .required(false)
                .value_name("HASH")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("targets")
                .short('t')
                .long("targets")
                .help("Target host(s) — comma-separated FQDNs or IPs")
                .long_help(
                    "One or more Windows hosts to scan, comma-separated.\n\
                     Examples:\n  \
                       -t dc01.corp.local\n  \
                       -t dc01.corp.local,fs01.corp.local,192.168.1.42\n\
                     Combine with --targets-file to merge a static list."
                )
                .required(false)
                .value_name("HOST[,HOST]")
                .value_parser(value_parser!(String)),
        )

        // Optional values
        .next_help_heading("OPTIONAL VALUES")
        .arg(
            Arg::new("targets-file")
                .short('T')
                .long("targets-file")
                .help("File with one host per line (# lines are comments)")
                .long_help(
                    "Path to a plain-text file containing one host (FQDN or IP) per line.\n\
                     Lines starting with '#' are ignored. Merged with -t if both are given.\n\
                     Duplicates are removed; order is preserved.\n\
                     Example file:\n  \
                       # DCs\n  \
                       dc01.corp.local\n  \
                       dc02.corp.local\n  \
                       # File servers\n  \
                       fs01.corp.local"
                )
                .required(false)
                .value_name("FILE")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Write JSON report to FILE instead of stdout")
                .long_help(
                    "Path to write the HasSession JSON report.\n\
                     When omitted the report is printed to stdout (pipe-friendly).\n\
                     The file is created or overwritten; parent directory must exist."
                )
                .required(false)
                .value_name("FILE")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("TCP connection timeout per host in seconds [default: 5]")
                .long_help(
                    "How many seconds to wait for a TCP 445 connection before giving up\n\
                     and recording a timeout error for that host. Does not affect RPC\n\
                     call latency (those time out at the OS level)."
                )
                .required(false)
                .value_name("SECS")
                .default_value("5")
                .value_parser(value_parser!(u64)),
        )

        // Optional flags
        .next_help_heading("OPTIONAL FLAGS")
        .arg(
            Arg::new("verbose")
                .short('v')
                .help("Increase verbosity (-v = DEBUG, -vv = TRACE)")
                .long_help(
                    "Each -v raises the log level:\n  \
                       (none)  INFO — only errors and the final JSON\n  \
                       -v      DEBUG — per-step traces on stderr\n  \
                       -vv     TRACE — wire-level NDR / PDU details"
                )
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Silence all [DEBUG] traces (stdout stays JSON-only)")
                .long_help(
                    "Suppress every [DEBUG] line on stderr so that stdout carries\n\
                     only the JSON report. Equivalent to piping stderr to /dev/null.\n\
                     Useful when chaining: HasSession-rs ... -q | jq '.by_user'"
                )
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("compact")
                .long("compact")
                .help("Print compact JSON instead of pretty-printed")
                .long_help(
                    "Emit the JSON report as a single line (no indentation).\n\
                     Saves bytes; useful when forwarding to a SIEM or another tool."
                )
                .required(false)
                .action(ArgAction::SetTrue),
        )

        // Collection modules
        .next_help_heading("COLLECTION METHOD")
        .arg(
            Arg::new("collection-method")
                .short('c')
                .long("collection-method")
                .help("Which RPC interfaces to query (default: All)")
                .long_help(
                    "Controls which of the three session-enumeration interfaces are used:\n\n  \
                       All          SRVSVC + WKSSVC + WINREG  (default)\n  \
                       SessionOnly  SRVSVC / NetrSessionEnum only\n               \
                                    - inbound SMB sessions; no admin needed on unpatched hosts\n  \
                       LogonOnly    WKSSVC / NetrWkstaUserEnum only\n               \
                                    - interactive logons; local admin on target required\n  \
                       RegistryOnly WINREG / HKEY_USERS only\n               \
                                    - loaded-profile SIDs; Remote Registry service must run\n\n\
                     Tip: start with SessionOnly on a wide scope, then rerun\n\
                     LogonOnly or RegistryOnly on interesting hosts."
                )
                .required(false)
                .value_name("METHOD")
                .value_parser(["All", "SessionOnly", "LogonOnly", "RegistryOnly"])
                .default_value("All"),
        )
}

// ─── Hash parsing (mirrors RustHound-CE) ─────────────────────────────────────

/// Parse an NT hash string into a 16-byte array.
///
/// Accepted formats (mirrors RustHound-CE's --hashes arg):
///   NTHASH                  — 32 hex chars
///   :NTHASH                 — colon prefix, LM part empty
///   LMHASH:NTHASH           — full pair, LM part ignored
///
/// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/ldap.rs
pub fn parse_nt_hash(input: &str) -> Result<[u8; 16], String> {
    let clean = input.trim();
    // Strip the LM part if present (right side of ':' is the NT hash).
    let nt = match clean.split_once(':') {
        Some((_lm, nt)) => nt,
        None             => clean,
    };
    if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid NT hash '{}': expected exactly 32 hex characters.\n  \
             Accepted formats: NTHASH | :NTHASH | LMHASH:NTHASH",
            nt
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in nt.as_bytes().chunks(2).enumerate() {
        // Safety: both bytes are guaranteed ASCII hex by the check above.
        bytes[i] = u8::from_str_radix(
            std::str::from_utf8(pair).unwrap(), 16
        ).unwrap();
    }
    Ok(bytes)
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Parse `std::env::args()` and return a populated [`Options`].
/// Calls `clap::Command::get_matches()` which exits with usage on error.
pub fn extract_args() -> Options {
    let matches = cli().get_matches();

    // Targets (merge -t and --targets-file)
    let mut targets: Vec<String> = matches
        .get_one::<String>("targets")
        .map(|s| {
            s.split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if let Some(path) = matches.get_one::<String>("targets-file") {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let h = line.trim();
                    if !h.is_empty() && !h.starts_with('#') {
                        targets.push(h.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] Cannot read targets-file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // De-dup while preserving order.
    let mut seen = std::collections::BTreeSet::new();
    targets.retain(|h| seen.insert(h.clone()));

    if targets.is_empty() {
        eprintln!(
            "[!] No targets specified. Use -t <HOST> or --targets-file <FILE>.\n\
             Run with --help for usage."
        );
        std::process::exit(1);
    }

    // ── Authentication: --password XOR --hashes ───────────────────────────
    let password   = matches.get_one::<String>("password").cloned().unwrap_or_default();
    let hashes_raw = matches.get_one::<String>("hashes").cloned();

    // Parse --hashes into a raw [u8; 16] if provided.
    let nt_hash: Option<[u8; 16]> = match &hashes_raw {
        Some(h) => {
            match parse_nt_hash(h) {
                Ok(bytes) => Some(bytes),
                Err(e)    => { eprintln!("[!] {e}"); std::process::exit(1); }
            }
        }
        None => None,
    };

    // Must have at least one credential.
    if nt_hash.is_none() && password.is_empty() {
        eprintln!(
            "[!] No credentials provided.\n  \
             Use -p <PASSWORD> or -H <NTHASH> (pass-the-hash).\n  \
             Run with --help for usage."
        );
        std::process::exit(1);
    }

    // Collection method
    let collection_method =
        match matches.get_one::<String>("collection-method").map(|s| s.as_str()).unwrap_or("All") {
            "SessionOnly"  => CollectionMethod::SessionOnly,
            "LogonOnly"    => CollectionMethod::LogonOnly,
            "RegistryOnly" => CollectionMethod::RegistryOnly,
            _              => CollectionMethod::All,
        };

    // Verbosity
    let verbose = match matches.get_count("verbose") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    Options {
        domain:   matches.get_one::<String>("domain").unwrap().clone(),
        username: matches.get_one::<String>("username").unwrap().clone(),
        password,
        nt_hash,
        targets,
        collection_method,
        timeout: *matches.get_one::<u64>("timeout").unwrap_or(&5),
        format: if matches.get_flag("compact") {
            OutputFormat::Compact
        } else {
            OutputFormat::Pretty
        },
        output: matches.get_one::<String>("output").cloned(),
        verbose,
        quiet: matches.get_flag("quiet"),
    }
}