//! HasSession-rs - enumerate "who is connected where" across Windows hosts via
//! three RPC paths and produce a HasSession-like JSON.
//!
//!   1. SRVSVC / NetrSessionEnum    inbound SMB sessions        (crate dcerpc)
//!   2. WKSSVC / NetrWkstaUserEnum  users logged on             (crate dcerpc)
//!   3. WINREG / HKEY_USERS         loaded-profile SIDs         (crate dcerpc)
//!
//! All diagnostic output goes through the `log` crate (env_logger backend).
//! The final JSON is the only thing ever written to stdout (via println!).
//!
//! Verbosity levels (mirrors RustHound-CE):
//!   (default)  INFO  - banner + scan summary
//!   -v         DEBUG - per-step RPC traces
//!   -vv        TRACE - NDR / PDU wire detail
//!   --quiet    OFF   - silence everything; stdout has JSON only
//!
//! Authorized use only: hosts you administer or are explicitly authorized to audit.
//!
//!   HasSession-rs -d CORP -u alice -p 'P@ssw0rd'               -t dc01.corp.local
//!   HasSession-rs -d CORP -u alice -H :31d6cfe0d16ae931b73c59d7e0c089c0 -t dc01

mod args;

use dcerpc::wkssvc::{WkstaUser, WkstaUserClient};
use dcerpc::rrp::{RegistryClient, RegistrySession};

use anyhow::{Context, Result};
use args::{OutputFormat, extract_args};
use colored::Colorize;
use dcerpc::srvsvc::SrvsvcClient;
use env_logger::Builder;
use log::{debug, error, info, trace, warn};
use serde::Serialize;
use smb2_client::SmbClient;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

// Logger init (RustHound-CE pattern)

/// Initialize env_logger with a custom format and the verbosity from CLI args.
///
/// Other crates are silenced to ERROR (mirrors RustHound-CE's filter_level).
/// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/main.rs
fn init_logger(verbose: log::LevelFilter, quiet: bool) {
    let level = if quiet { log::LevelFilter::Off } else { verbose };

    Builder::new()
        .format(|buf, record| {
            let prefix = match record.level() {
                log::Level::Error => "[ERROR]".red().bold().to_string(),
                log::Level::Warn  => "[WARN-]".yellow().bold().to_string(),
                log::Level::Info  => "[INFO-]".green().bold().to_string(),
                log::Level::Debug => "[DEBUG]".cyan().to_string(),
                log::Level::Trace => "[TRACE]".blue().to_string(),
            };
            writeln!(buf, "{} {}", prefix, record.args())
        })
        .filter(Some("HasSession_rs"), level)
        .filter_level(log::LevelFilter::Error)
        .init();
}

// Internal collection types

struct SmbSession { user: String, client: String }

struct HostFindings {
    host:         String,
    smb_sessions: Vec<SmbSession>,
    logged_on:    Vec<WkstaUser>,
    registry:     Vec<RegistrySession>,
    errors:       Vec<String>,
}

// JSON output types

#[derive(Serialize)]
struct SessionEdge {
    principal: String,
    host:      String,
    method:    &'static str,
}

#[derive(Serialize)]
struct HasSessionReport {
    domain:        String,
    hosts_scanned: Vec<String>,
    edge_count:    usize,
    edges:         Vec<SessionEdge>,
    by_user:       BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors:        Vec<String>,
}

// Entry point

#[tokio::main]
async fn main() -> Result<()> {
    let opts = extract_args();
    init_logger(opts.verbose, opts.quiet);

    // Auth method display
    let auth_label = match &opts.nt_hash {
        Some(h) => format!("NTLMv2 PTH [{:02x}{:02x}{:02x}…]", h[0], h[1], h[2]),
        None    => "NTLMv2 password".to_string(),
    };

    info!("Domain        : {}", opts.domain.bold());
    info!("User          : {}", opts.username.bold());
    info!("Auth          : {}", auth_label.bold());
    info!("Targets       : {}", opts.targets.len());
    info!("Method        : {:?}", opts.collection_method);
    info!("Timeout       : {}s", opts.timeout);
    info!("Verbosity     : {:?}", opts.verbose);

    // Scan
    let mut all: Vec<HostFindings> = Vec::new();
    for host in &opts.targets {
        debug!("==================== {host} ====================");
        all.push(enumerate_host(
            host, &opts.domain, &opts.username, &opts.password,
            opts.nt_hash.as_ref(),
            &opts.collection_method, opts.timeout,
        ).await);
    }

    // Correlate
    let mut edges: Vec<SessionEdge> = Vec::new();
    let mut by_user: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();

    let mut push = |principal: String, host: &str, method: &'static str| {
        if principal.is_empty() || principal == "?" { return; }
        by_user.entry(principal.clone()).or_default().insert(host.to_string());
        edges.push(SessionEdge { principal, host: host.to_string(), method });
    };

    for f in &all {
        errors.extend(f.errors.iter().cloned());

        for s in &f.smb_sessions {
            push(s.user.clone(), &f.host, "NetSessionEnum");
        }

        let mut machine_skipped = 0usize;
        for u in &f.logged_on {
            if u.username.ends_with('$') {
                machine_skipped += 1;
                trace!("Skipping machine account: {}\\{}", u.logon_domain, u.username);
                continue;
            }
            let p = if u.logon_domain.is_empty() { u.username.clone() }
                    else { format!("{}\\{}", u.logon_domain, u.username) };
            push(p, &f.host, "NetWkstaUserEnum");
        }
        if machine_skipped > 0 {
            debug!("[{}] Filtered {} machine account(s) from WKSSVC output.", f.host, machine_skipped);
        }

        for r in &f.registry {
            push(r.sid.clone(), &f.host, "RegistryHKU");
        }
    }

    let report = HasSessionReport {
        domain: opts.domain.clone(),
        hosts_scanned: opts.targets.clone(),
        edge_count: edges.len(),
        edges,
        by_user: by_user.into_iter().map(|(k,v)|(k,v.into_iter().collect())).collect(),
        errors,
    };

    info!("Scan complete - {} edge(s) across {} host(s).",
          report.edge_count, report.hosts_scanned.len());

    // JSON: stdout only (println! intentional, not log)
    let json = match opts.format {
        OutputFormat::Pretty  => serde_json::to_string_pretty(&report),
        OutputFormat::Compact => serde_json::to_string(&report),
    }.context("JSON serialization")?;

    match &opts.output {
        Some(path) => {
            std::fs::write(path, &json).with_context(|| format!("writing to {path}"))?;
            info!("Report written to {path}");
        }
        None => println!("{json}"),
    }

    Ok(())
}

// Per-host enumeration

async fn enumerate_host(
    host: &str, domain: &str, user: &str, password: &str,
    nt_hash: Option<&[u8; 16]>,
    method: &args::CollectionMethod, _timeout: u64,
) -> HostFindings {
    let mut f = HostFindings { host: host.to_string(),
        smb_sessions: Vec::new(), logged_on: Vec::new(),
        registry: Vec::new(), errors: Vec::new() };

    // TCP + NEGOTIATE
    debug!("[{host}] TCP 445 + SMB2 NEGOTIATE ...");
    let mut smb = match SmbClient::connect(&format!("{host}:445")).await {
        Ok(c)  => c,
        Err(e) => {
            let m = format!("{host} connect: {e}");
            error!("{m}"); f.errors.push(m); return f;
        }
    };

    // SESSION_SETUP — NTLMv2 password OR pass-the-hash
    match nt_hash {
        Some(hash) => {
            debug!("[{host}] SESSION_SETUP NTLMv2 PTH ({domain}\\{user}) ...");
            if let Err(e) = smb.login_hash(host, domain, user, hash).await {
                let m = format!("{host} auth (PTH): {e}");
                error!("{m}"); f.errors.push(m); return f;
            }
            info!("[{host}] Auth validated - NTLMv2 PTH for {}\\{}", domain.bold(), user.bold());
        }
        None => {
            debug!("[{host}] SESSION_SETUP NTLMv2 ({domain}\\{user}) ...");
            if let Err(e) = smb.login(host, domain, user, password).await {
                let m = format!("{host} auth: {e}");
                error!("{m}"); f.errors.push(m); return f;
            }
            info!("[{host}] Auth validated - NTLMv2 session for {}\\{}", domain.bold(), user.bold());
        }
    }

    // TREE_CONNECT IPC$
    trace!("[{host}] TREE_CONNECT \\\\{host}\\IPC$ ...");
    if let Err(e) = smb.tree_connect(&format!(r"\\{host}\IPC$")).await {
        let m = format!("{host} IPC$: {e}");
        warn!("{m}"); f.errors.push(m); return f;
    }
    trace!("[{host}] IPC$ mounted");

    // SRVSVC
    if method.srvsvc() {
        debug!("[{host}] [SRVSVC] NetrSessionEnum (opnum 12, level 10) ...");
        match srvsvc_sessions(&mut smb).await {
            Ok((sessions, rc)) => {
                if rc == 5 {
                    let msg = format!(
                        "[{host}] SRVSVC rc=5 (ERROR_ACCESS_DENIED) \
                         - SrvsvcSessionInfo ACL blocks non-admin enumeration.\n  \
                         - Use an admin account, or --collection-method LogonOnly/RegistryOnly."
                    );
                    warn!("{msg}"); f.errors.push(msg);
                } else {
                    info!("[{host}] SRVSVC - {} SMB session(s)  (rc={rc})", sessions.len());
                    if sessions.is_empty() {
                        debug!("[{host}] 0 SMB sessions - no inbound connections at this moment.");
                    }
                    for s in &sessions {
                        debug!("[{host}]   session: {} <- {}", s.user.cyan(), s.client);
                    }
                    f.smb_sessions = sessions;
                }
            }
            Err(e) => {
                let m = format!("{host} SRVSVC: {e}");
                warn!("{m}"); f.errors.push(m);
            }
        }
    }

    // WKSSVC
    if method.wkssvc() {
        debug!("[{host}] [WKSSVC] NetrWkstaUserEnum (opnum 2, level 1) ...");
        match enum_wksta(&mut smb).await {
            Ok((users, rc)) => {
                if rc == 5 {
                    let msg = format!(
                        "[{host}] WKSSVC rc=5 (ERROR_ACCESS_DENIED) - local admin required."
                    );
                    warn!("{msg}"); f.errors.push(msg);
                } else {
                    let raw_count = users.len();
                    let mut seen_wksta = BTreeSet::new();
                    let users: Vec<_> = users
                        .into_iter()
                        .filter(|u| seen_wksta.insert((u.logon_domain.clone(), u.username.clone())))
                        .collect();
                    if raw_count != users.len() {
                        debug!("[{host}] WKSSVC dedup: {raw_count} sessions - {} unique principal(s)",
                               users.len());
                    }
                    info!("[{host}] WKSSVC - {} unique logged-on principal(s)  (rc={rc}, raw={raw_count})",
                          users.len());
                    for u in &users {
                        debug!("[{host}]   logon: {}\\{}  (server: {})",
                               u.logon_domain.cyan(), u.username, u.logon_server);
                    }
                    f.logged_on = users;
                }
            }
            Err(e) => {
                let m = format!("{host} WKSSVC: {e}");
                warn!("{m}");
                debug!("[{host}] WKSSVC usually requires local admin on the target.");
                f.errors.push(m);
            }
        }
    }

    // WINREG
    if method.registry() {
        debug!("[{host}] [WINREG] HKEY_USERS subkey enum (OpenHKU + BaseRegEnumKey) ...");
        match enum_registry(&mut smb, domain, user, password, host).await {
            Ok(sids) => {
                info!("[{host}] WINREG - {} loaded profile SID(s)", sids.len());
                for s in &sids { debug!("[{host}]   SID {}", s.sid.yellow()); }
                f.registry = sids;
            }
            Err(e) => {
                let m = format!("{host} WINREG: {e}");
                warn!("{m}");
                debug!("[{host}] Remote Registry service may be stopped - sc start remoteregistry");
                f.errors.push(m);
            }
        }
    }
    f
}

// Isolated RPC calls

async fn srvsvc_sessions(smb: &mut SmbClient) -> Result<(Vec<SmbSession>, u32)> {
    let pipe = smb.open_pipe("srvsvc").await?;
    let mut srv = SrvsvcClient::bind(smb, pipe).await?;
    let (sessions, rc) = srv.enum_sessions().await?;
    Ok((sessions.into_iter().map(|s| SmbSession { user: s.user, client: s.client }).collect(), rc))
}

async fn enum_wksta(smb: &mut SmbClient) -> Result<(Vec<WkstaUser>, u32)> {
    let pipe = smb.open_pipe("wkssvc").await?;
    let mut wk = WkstaUserClient::bind(smb, pipe).await?;
    Ok(wk.enum_users().await?)
}

async fn enum_registry(smb: &mut SmbClient, domain: &str, user: &str,
                        password: &str, host: &str) -> Result<Vec<RegistrySession>> {
    let mut reg = RegistryClient::connect(smb, domain, user, password, host)
        .await.map_err(|e| anyhow::anyhow!("{e}"))?;
    reg.logged_on_sids().await.map_err(|e| anyhow::anyhow!("{e}"))
}