//! rex-discover — find live Rex servers on your Tailscale tailnet and/or LAN.
//!
//! Strategy:
//!   1. Tailnet: `tailscale status --json` → probe Online peers with `rex -S … ls`.
//!   2. LAN: derive private /24s from local NICs (or `--cidr`), TCP-probe 443/7297
//!      first, then only handshake hosts that answered.
//! A hit is confirmed when `rex -S <addr> ls` output contains the session
//! table header "LABEL". Results are merged and deduped by address.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures::stream::{self, StreamExt};
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

const DEFAULT_CONCURRENCY: usize = 16;
const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// TCP connect timeout for the LAN port sweep (keep short — we fan out hard).
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Parser, Debug)]
#[command(
    name = "rex-discover",
    about = "Discover live Rex servers on Tailscale and local LAN",
    long_about = "By default scans both your Tailscale tailnet (online nodes) and \
local private LAN (/24). Uses a real `rex -S <addr> ls` handshake; a hit is \
confirmed when output contains \"LABEL\". LAN first TCP-probes 443/7297 so we \
don't slow-handshake every IP. Use --tailnet-only / --lan-only to restrict; \
--json for machine-readable output; `add` to register into local Rex hosts."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Only scan the Tailscale tailnet (skip LAN).
    #[arg(long, global = true, conflicts_with = "lan_only")]
    tailnet_only: bool,

    /// Only scan the local LAN (skip Tailscale).
    #[arg(long, global = true, conflicts_with = "tailnet_only")]
    lan_only: bool,

    /// Also probe Offline Tailscale nodes (default: Online only).
    #[arg(long, global = true)]
    all: bool,

    /// Emit JSON array instead of a human-readable table.
    #[arg(long, global = true)]
    json: bool,

    /// Max concurrent probes (default 16).
    #[arg(long, global = true, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Per-handshake timeout in seconds (default 5).
    #[arg(long, global = true, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// LAN CIDR to scan (repeatable). If omitted, auto-detect private /24s
    /// from local interfaces (Linux `ip -json addr` or macOS `ifconfig`).
    #[arg(long = "cidr", value_name = "CIDR", global = true)]
    cidrs: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover live Rex servers and `rex hosts add` each one locally.
    /// Skips the local Self / loopback. LAN shortnames look like `lan-42`.
    Add {
        /// Dry-run: print the `rex hosts add` commands without running them.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Subset of `tailscale status --json`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleStatus {
    #[serde(rename = "Self")]
    self_node: Node,
    #[serde(default)]
    peer: std::collections::HashMap<String, Node>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Node {
    #[serde(rename = "DNSName")]
    dns_name: String,
    #[serde(default)]
    online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Tailnet,
    Lan,
}

impl Source {
    fn as_str(&self) -> &'static str {
        match self {
            Source::Tailnet => "tailnet",
            Source::Lan => "lan",
        }
    }
}

#[derive(Debug, Clone)]
struct LiveRex {
    source: Source,
    /// Short display name: DNS first label, or the LAN IP / `lan-<octet>`.
    name: String,
    /// Address that answered, e.g. "https://omarchy-rex…ts.net" or "http://192.168.1.10:7297".
    addr: String,
    /// "builtin-443" or "7297".
    mode: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let handshake_timeout = Duration::from_secs(cli.timeout.max(1));
    let concurrency = cli.concurrency.max(1);

    // `rex` is always required (handshake + add). `tailscale` only if we scan it.
    ensure_bin_in_path("rex")?;
    let do_tailnet = !cli.lan_only;
    let do_lan = !cli.tailnet_only;
    if do_tailnet {
        ensure_bin_in_path("tailscale")?;
    }

    let mut lives = Vec::new();
    if do_tailnet {
        match discover_tailnet(cli.all, concurrency, handshake_timeout).await {
            Ok(mut v) => lives.append(&mut v),
            Err(e) => eprintln!("tailnet scan failed: {e:#}"),
        }
    }
    if do_lan {
        match discover_lan(&cli.cidrs, concurrency, handshake_timeout).await {
            Ok(mut v) => lives.append(&mut v),
            Err(e) => eprintln!("lan scan failed: {e:#}"),
        }
    }

    // Dedupe by addr (prefer the first occurrence — tailnet listed first).
    lives = dedupe_by_addr(lives);
    lives.sort_by(|a, b| {
        a.source
            .as_str()
            .cmp(b.source.as_str())
            .then(a.name.cmp(&b.name))
            .then(a.mode.cmp(b.mode))
    });

    match cli.command {
        None => {
            if cli.json {
                print_json(&lives);
            } else {
                print_table(&lives);
            }
        }
        Some(Commands::Add { dry_run }) => {
            add_hosts(&lives, dry_run, do_tailnet).await?;
        }
    }
    Ok(())
}

fn ensure_bin_in_path(name: &str) -> Result<()> {
    let found = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p: PathBuf = dir.join(name);
                p.is_file()
            })
        })
        .unwrap_or(false);
    if !found {
        bail!(
            "`{name}` not found in PATH. Install it first, then re-run rex-discover.\n\
             - tailscale: https://tailscale.com/download\n\
             - rex:       your usual Rex CLI install"
        );
    }
    Ok(())
}

fn dedupe_by_addr(lives: Vec<LiveRex>) -> Vec<LiveRex> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for l in lives {
        if seen.insert(l.addr.clone()) {
            out.push(l);
        }
    }
    out
}

// ─── Tailnet ────────────────────────────────────────────────────────────────

async fn discover_tailnet(
    probe_all: bool,
    concurrency: usize,
    handshake_timeout: Duration,
) -> Result<Vec<LiveRex>> {
    let status = fetch_tailscale_status().await?;

    let mut candidates: Vec<(String, String)> = Vec::new(); // (short, dns)
    push_tailnet_candidate(&mut candidates, &status.self_node, probe_all);
    for peer in status.peer.values() {
        push_tailnet_candidate(&mut candidates, peer, probe_all);
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    if candidates.is_empty() {
        eprintln!("tailnet: (no nodes to probe — is Tailscale up? try --all)");
        return Ok(Vec::new());
    }

    eprintln!(
        "tailnet: probing {} node(s) (concurrency {}, timeout {}s)…",
        candidates.len(),
        concurrency,
        handshake_timeout.as_secs()
    );

    let results: Vec<Option<LiveRex>> = stream::iter(candidates.into_iter())
        .map(|(name, dns)| async move {
            probe_host_addrs(
                Source::Tailnet,
                name,
                &format!("https://{dns}"),
                &format!("http://{dns}:7297"),
                handshake_timeout,
            )
            .await
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}

fn push_tailnet_candidate(out: &mut Vec<(String, String)>, node: &Node, probe_all: bool) {
    if !probe_all && !node.online {
        return;
    }
    let dns = normalize_dns(&node.dns_name);
    if dns.is_empty() {
        return;
    }
    out.push((short_name(&dns), dns));
}

fn normalize_dns(dns: &str) -> String {
    dns.trim_end_matches('.').to_string()
}

fn short_name(dns: &str) -> String {
    dns.split('.').next().unwrap_or(dns).to_string()
}

async fn fetch_tailscale_status() -> Result<TailscaleStatus> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to spawn `tailscale status --json`")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`tailscale status --json` failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            err.trim()
        );
    }

    serde_json::from_slice(&output.stdout)
        .context("failed to parse `tailscale status --json` output")
}

// ─── LAN ────────────────────────────────────────────────────────────────────

async fn discover_lan(
    cidr_args: &[String],
    concurrency: usize,
    handshake_timeout: Duration,
) -> Result<Vec<LiveRex>> {
    let nets = if cidr_args.is_empty() {
        detect_private_slash24s().await?
    } else {
        parse_cidrs(cidr_args)?
    };

    if nets.is_empty() {
        eprintln!("lan: (no private /24 found; pass --cidr 192.168.1.0/24)");
        return Ok(Vec::new());
    }

    // Enumerate host IPs (skip network / broadcast for IPv4).
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for net in &nets {
        eprintln!("lan: scanning {net}");
        for host in net.hosts() {
            ips.push(host);
        }
    }
    // Dedup across overlapping CIDRs.
    ips.sort();
    ips.dedup();

    eprintln!(
        "lan: TCP-probing {} host(s) on :443 and :7297 (concurrency {})…",
        ips.len(),
        concurrency
    );

    // Phase 1: fast TCP connect to 443 and 7297.
    #[derive(Clone, Copy)]
    struct OpenPorts {
        p443: bool,
        p7297: bool,
    }
    let open: Vec<(Ipv4Addr, OpenPorts)> = stream::iter(ips.into_iter())
        .map(|ip| async move {
            let p443 = tcp_open(SocketAddr::new(IpAddr::V4(ip), 443)).await;
            let p7297 = tcp_open(SocketAddr::new(IpAddr::V4(ip), 7297)).await;
            if p443 || p7297 {
                Some((ip, OpenPorts { p443, p7297 }))
            } else {
                None
            }
        })
        .buffer_unordered(concurrency.saturating_mul(4).max(32)) // TCP is cheap; go wider
        .filter_map(|x| async move { x })
        .collect()
        .await;

    if open.is_empty() {
        eprintln!("lan: (no hosts with :443 or :7297 open)");
        return Ok(Vec::new());
    }
    eprintln!(
        "lan: {} host(s) with open ports — running rex handshake…",
        open.len()
    );

    // Phase 2: rex handshake only on open ports.
    let results: Vec<Option<LiveRex>> = stream::iter(open.into_iter())
        .map(|(ip, ports)| async move {
            let https = if ports.p443 {
                Some(format!("https://{ip}"))
            } else {
                None
            };
            let http7297 = if ports.p7297 {
                Some(format!("http://{ip}:7297"))
            } else {
                None
            };
            // Prefer 443 when both open.
            if let Some(ref addr) = https {
                if probe_rex(addr, handshake_timeout).await {
                    return Some(LiveRex {
                        source: Source::Lan,
                        name: ip.to_string(),
                        addr: addr.clone(),
                        mode: "builtin-443",
                    });
                }
            }
            if let Some(ref addr) = http7297 {
                if probe_rex(addr, handshake_timeout).await {
                    return Some(LiveRex {
                        source: Source::Lan,
                        name: ip.to_string(),
                        addr: addr.clone(),
                        mode: "7297",
                    });
                }
            }
            None
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}

fn parse_cidrs(args: &[String]) -> Result<Vec<Ipv4Net>> {
    let mut nets = Vec::new();
    for s in args {
        let net: IpNet = s
            .parse()
            .with_context(|| format!("invalid --cidr `{s}`"))?;
        match net {
            IpNet::V4(v4) => nets.push(v4),
            IpNet::V6(_) => bail!("IPv6 CIDR not supported yet: {s}"),
        }
    }
    Ok(nets)
}

/// Auto-detect private IPv4 /24s from local interfaces.
/// Linux: `ip -json addr`. macOS/BSD: `ifconfig` text parse.
async fn detect_private_slash24s() -> Result<Vec<Ipv4Net>> {
    // Prefer `ip -json addr` when available (Linux).
    if which_exists("ip") {
        if let Ok(nets) = detect_via_ip_json().await {
            if !nets.is_empty() {
                return Ok(nets);
            }
        }
    }
    // Fallback: ifconfig (macOS / BSD / some Linux).
    if which_exists("ifconfig") {
        if let Ok(nets) = detect_via_ifconfig().await {
            if !nets.is_empty() {
                return Ok(nets);
            }
        }
    }
    Ok(Vec::new())
}

fn which_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join(name).is_file())
        })
        .unwrap_or(false)
}

async fn detect_via_ip_json() -> Result<Vec<Ipv4Net>> {
    let output = Command::new("ip")
        .args(["-json", "addr"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("spawn `ip -json addr`")?;
    if !output.status.success() {
        bail!("`ip -json addr` failed");
    }
    let ifaces: Vec<Value> = serde_json::from_slice(&output.stdout)
        .context("parse `ip -json addr`")?;
    let mut nets = Vec::new();
    for iface in ifaces {
        // Skip loopback / down-ish — we still filter by private + not 127.
        let addrs = iface
            .get("addr_info")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for a in addrs {
            if a.get("family").and_then(|f| f.as_str()) != Some("inet") {
                continue;
            }
            let local = match a.get("local").and_then(|l| l.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let ip: Ipv4Addr = match local.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if let Some(net) = private_slash24(ip) {
                nets.push(net);
            }
        }
    }
    nets.sort();
    nets.dedup();
    Ok(nets)
}

async fn detect_via_ifconfig() -> Result<Vec<Ipv4Net>> {
    let output = Command::new("ifconfig")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("spawn `ifconfig`")?;
    if !output.status.success() {
        bail!("`ifconfig` failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut nets = Vec::new();
    // Match both Linux (`inet 192.168.1.2`) and macOS (`inet 192.168.1.2 netmask 0xffffff00`).
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("inet ") {
            continue;
        }
        // Skip inet6.
        if line.starts_with("inet6 ") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // "inet"
        let Some(addr_s) = parts.next() else { continue };
        // Linux sometimes prints `inet 192.168.1.2/24` — strip prefixlen.
        let addr_s = addr_s.split('/').next().unwrap_or(addr_s);
        let Ok(ip) = Ipv4Addr::from_str(addr_s) else { continue };
        if let Some(net) = private_slash24(ip) {
            nets.push(net);
        }
    }
    nets.sort();
    nets.dedup();
    Ok(nets)
}

/// Return the containing private RFC1918 /24 for this address, or None.
fn private_slash24(ip: Ipv4Addr) -> Option<Ipv4Net> {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
        return None;
    }
    // RFC1918: 10/8, 172.16/12, 192.168/16.
    let o = ip.octets();
    let is_private = o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168);
    if !is_private {
        return None;
    }
    // Force /24 around this host.
    let base = Ipv4Addr::new(o[0], o[1], o[2], 0);
    Ipv4Net::new(base, 24).ok()
}

async fn tcp_open(addr: SocketAddr) -> bool {
    matches!(
        timeout(TCP_PROBE_TIMEOUT, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

// ─── Shared handshake ───────────────────────────────────────────────────────

/// Try https (443) then http:7297; return first live Rex (prefer 443).
async fn probe_host_addrs(
    source: Source,
    name: String,
    https: &str,
    http7297: &str,
    handshake_timeout: Duration,
) -> Option<LiveRex> {
    if probe_rex(https, handshake_timeout).await {
        return Some(LiveRex {
            source,
            name,
            addr: https.to_string(),
            mode: "builtin-443",
        });
    }
    if probe_rex(http7297, handshake_timeout).await {
        return Some(LiveRex {
            source,
            name,
            addr: http7297.to_string(),
            mode: "7297",
        });
    }
    None
}

/// Real handshake: `rex -S <addr> ls` must print "LABEL".
async fn probe_rex(addr: &str, handshake_timeout: Duration) -> bool {
    let fut = async {
        let output = Command::new("rex")
            .args(["-S", addr, "ls"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .ok()?;
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        Some(combined.contains("LABEL"))
    };

    matches!(timeout(handshake_timeout, fut).await, Ok(Some(true)))
}

// ─── Output ─────────────────────────────────────────────────────────────────

fn print_table(lives: &[LiveRex]) {
    if lives.is_empty() {
        println!("(no live Rex servers found)");
        return;
    }
    let w_src = "tailnet".len();
    let w_name = lives.iter().map(|l| l.name.len()).max().unwrap_or(4).max(4);
    let w_addr = lives.iter().map(|l| l.addr.len()).max().unwrap_or(4).max(4);
    let w_mode = "builtin-443".len();

    println!(
        "{:<w_src$}  {:<w_name$}  {:<w_addr$}  {:<w_mode$}",
        "SOURCE",
        "NAME",
        "ADDR",
        "MODE",
        w_src = w_src,
        w_name = w_name,
        w_addr = w_addr,
        w_mode = w_mode
    );
    println!(
        "{:-<w_src$}  {:-<w_name$}  {:-<w_addr$}  {:-<w_mode$}",
        "",
        "",
        "",
        "",
        w_src = w_src,
        w_name = w_name,
        w_addr = w_addr,
        w_mode = w_mode
    );
    for l in lives {
        println!(
            "{:<w_src$}  {:<w_name$}  {:<w_addr$}  {:<w_mode$}",
            l.source.as_str(),
            l.name,
            l.addr,
            l.mode,
            w_src = w_src,
            w_name = w_name,
            w_addr = w_addr,
            w_mode = w_mode
        );
    }
    println!();
    println!("{} live Rex server(s)", lives.len());
}

fn print_json(lives: &[LiveRex]) {
    let arr: Vec<_> = lives
        .iter()
        .map(|l| {
            json!({
                "source": l.source.as_str(),
                "name": l.name,
                "addr": l.addr,
                "mode": l.mode,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&arr).unwrap());
}

// ─── add ────────────────────────────────────────────────────────────────────

fn lan_shortname(name_or_ip: &str) -> String {
    // Prefer last octet: 192.168.1.42 → lan-42. Fallback: sanitize whole thing.
    if let Ok(ip) = Ipv4Addr::from_str(name_or_ip) {
        return format!("lan-{}", ip.octets()[3]);
    }
    format!("lan-{}", name_or_ip.replace(['.', ':'], "-"))
}

async fn add_hosts(lives: &[LiveRex], dry_run: bool, have_tailscale: bool) -> Result<()> {
    // Figure out Self short name so we don't add ourselves.
    let self_short = if have_tailscale {
        match fetch_tailscale_status().await {
            Ok(st) => Some(short_name(&normalize_dns(&st.self_node.dns_name))),
            Err(_) => None,
        }
    } else {
        None
    };

    if lives.is_empty() {
        println!("(nothing to add)");
        return Ok(());
    }

    for l in lives {
        let host_name = match l.source {
            Source::Tailnet => l.name.clone(),
            Source::Lan => lan_shortname(&l.name),
        };

        if self_short.as_deref() == Some(host_name.as_str())
            || self_short.as_deref() == Some(l.name.as_str())
        {
            println!("skip  {host_name}  (this is Self)");
            continue;
        }

        if dry_run {
            println!("would: rex hosts add {host_name} {}", l.addr);
            continue;
        }

        print!("add   {host_name} -> {} … ", l.addr);
        let output = Command::new("rex")
            .args(["hosts", "add", &host_name, &l.addr])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| {
                format!("failed to spawn `rex hosts add {host_name} {}`", l.addr)
            })?;

        if output.status.success() {
            let out = String::from_utf8_lossy(&output.stdout);
            let msg = out.trim();
            if msg.is_empty() {
                println!("ok");
            } else {
                println!("ok ({msg})");
            }
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            let out = String::from_utf8_lossy(&output.stdout);
            let detail = if !err.trim().is_empty() {
                err.trim().to_string()
            } else {
                out.trim().to_string()
            };
            println!("FAILED: {detail}");
        }
    }
    Ok(())
}
