use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::Parser;
use http::Method;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use url::Url;

use prototalpid_cli::{
    MoleClient, MoleClientOptions, WalletStore, default_store_path, normalize_origin_input,
};
use prototalpid_http::tls::build_http_client;

/// A `curl`-subset HTTPS client implementing Moderation of unLinkable Endorsements (MOLE).
#[derive(Debug, Parser)]
#[command(name = "prototalpid-cli", version, about)]
struct Cli {
    /// Target URL(s) to request (or Anchor URL(s) when `--mole-endorse` is set).
    #[arg(value_name = "URL")]
    urls: Vec<Url>,

    /// HTTP request method (`GET`, `POST`, `HEAD`, etc.).
    #[arg(short = 'X', long = "request")]
    request: Option<String>,

    /// Extra HTTP header (`Name: Value`); may be repeated.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// HTTP POST data (sets method to `POST` if `-X` is omitted).
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// HTTP POST binary data (`@file` or literal string).
    #[arg(long = "data-binary")]
    data_binary: Option<String>,

    /// Include HTTP response status line and headers in output.
    #[arg(short = 'i', long = "include")]
    include: bool,

    /// Fetch headers only (`HEAD` request).
    #[arg(short = 'I', long = "head")]
    head: bool,

    /// Verbose HTTP and MOLE protocol trace on stderr.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Silent mode (suppresses progress/non-error diagnostic noise).
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Show error messages even when `-s` is enabled.
    #[arg(short = 'S', long = "show-error")]
    show_error: bool,

    /// Write response body to `<FILE>` instead of stdout.
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Fail silently with exit code 22 on HTTP status >= 400.
    #[arg(short = 'f', long = "fail")]
    fail: bool,

    /// Format string printed after transfer (`%{http_code}`, `%{url_effective}`, `\n`).
    #[arg(short = 'w', long = "write-out")]
    write_out: Option<String>,

    /// Follow HTTP `3xx` redirects (never redirects stateful MOLE grant POSTs).
    #[arg(short = 'L', long = "location")]
    location: bool,

    /// Pass literal `name=val` cookies or load a Netscape cookie-jar file.
    #[arg(short = 'b', long = "cookie")]
    cookie: Option<String>,

    /// Export cookies to a Netscape cookie-jar file on exit.
    #[arg(short = 'c', long = "cookie-jar")]
    cookie_jar: Option<PathBuf>,

    /// Allow insecure TLS server connections without certificate verification.
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

    /// Custom CA certificate bundle PEM file.
    #[arg(long = "cacert")]
    cacert: Option<PathBuf>,

    /// Override default XDG SQLite wallet path (`$XDG_DATA_HOME/prototalpid/state.db`).
    #[arg(long = "mole-store")]
    mole_store: Option<PathBuf>,

    /// Bypass all MOLE headers and `401` challenge handling.
    #[arg(long = "mole-disable")]
    mole_disable: bool,

    /// Acquire EC-IHAT Endorsements from the specified Anchor URL(s).
    #[arg(long = "mole-endorse")]
    mole_endorse: bool,

    /// Batch size requested during `--mole-endorse`.
    #[arg(long = "mole-batch-count", default_value_t = 4)]
    mole_batch_count: u16,

    /// Non-interactive answer for Anchor prompt challenges (useful in scripts/tests).
    #[arg(long = "mole-prompt-answer")]
    mole_prompt_answer: Option<String>,

    /// Explicitly send `signoff-0001` for an active held session at `<ORIGIN_OR_URL>`.
    #[arg(long = "mole-signoff")]
    mole_signoff: Option<String>,

    /// Automatically send `signoff-0001` for any active held session before exiting.
    #[arg(long = "mole-signoff-on-exit")]
    mole_signoff_on_exit: bool,

    /// Print stored MOLE endorsements, usable credentials, active sessions, and cookies as JSON.
    #[arg(long = "mole-status")]
    mole_status: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let quiet_errors = cli.silent && !cli.show_error;
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            if !quiet_errors {
                eprintln!("prototalpid-cli: {err:#}");
            }
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let store_path = match cli.mole_store {
        Some(ref p) => p.clone(),
        None => default_store_path().context("failed to resolve XDG data directory")?,
    };
    let store = Arc::new(WalletStore::open(Some(&store_path))?);

    let mut explicit_cookie_header = None;
    if let Some(ref b_arg) = cli.cookie {
        if b_arg.contains('=') {
            explicit_cookie_header = Some(b_arg.clone());
        } else {
            store.import_cookie_jar(std::path::Path::new(b_arg))?;
        }
    }

    let http_client = build_http_client(cli.insecure, cli.cacert.as_deref())?;
    let mut opts = MoleClientOptions::new(http_client);
    opts.mole_disabled = cli.mole_disable;
    opts.verbose = cli.verbose;
    opts.follow_redirects = cli.location;
    opts.explicit_cookie_header = explicit_cookie_header;
    opts.prompt_answer_override = cli.mole_prompt_answer.clone();

    let client = MoleClient::new(store.clone(), opts);

    if let Some(ref signoff_target) = cli.mole_signoff {
        let origin = normalize_origin_input(signoff_target)?;
        let _ = client.signoff_origin(&origin).await?;
    }

    if cli.mole_endorse {
        if cli.urls.is_empty() {
            bail!("--mole-endorse requires at least one Anchor URL");
        }
        for url in &cli.urls {
            let count = client.acquire_endorsements(url, cli.mole_batch_count).await?;
            if !cli.silent {
                println!(
                    "Acquired {count} EC-IHAT endorsement(s) from {}",
                    url.as_str()
                );
            }
        }
        if cli.mole_status {
            let summary = store.status_summary()?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        if let Some(ref jar) = cli.cookie_jar {
            store.export_cookie_jar(jar)?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut exit_code = ExitCode::SUCCESS;

    if !cli.urls.is_empty() {
        let (body_bytes, has_body) = load_request_body(&cli)?;
        let method_str = if let Some(ref m) = cli.request {
            m.as_str()
        } else if cli.head {
            "HEAD"
        } else if has_body {
            "POST"
        } else {
            "GET"
        };
        let method = Method::from_bytes(method_str.as_bytes()).context("invalid HTTP method")?;
        let mut user_headers = parse_user_headers(&cli.headers)?;
        if has_body && !user_headers.contains_key(CONTENT_TYPE) {
            user_headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
        }

        for url in &cli.urls {
            let resp = client
                .execute_request(method.clone(), url.clone(), user_headers.clone(), body_bytes.clone())
                .await?;

            if cli.fail && resp.status.as_u16() >= 400 {
                if !cli.silent || cli.show_error {
                    eprintln!(
                        "prototalpid-cli: The requested URL returned error: {}",
                        resp.status
                    );
                }
                exit_code = ExitCode::from(22);
            } else {
                write_response(&cli, &resp)?;
            }

            if let Some(ref fmt) = cli.write_out {
                let rendered = fmt
                    .replace("%{http_code}", &resp.status.as_u16().to_string())
                    .replace("%{url_effective}", resp.effective_url.as_str())
                    .replace("\\n", "\n");
                print!("{rendered}");
                io::stdout().flush()?;
            }
        }
    }

    if cli.mole_signoff_on_exit {
        client.signoff_all_held().await?;
    }

    if cli.mole_status {
        let summary = store.status_summary()?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if cli.urls.is_empty() && cli.mole_signoff.is_none() {
        bail!("specify at least one URL, --mole-status, or --mole-signoff");
    }

    if let Some(ref jar) = cli.cookie_jar {
        store.export_cookie_jar(jar)?;
    }

    Ok(exit_code)
}

fn load_request_body(cli: &Cli) -> anyhow::Result<(Bytes, bool)> {
    if let Some(ref db) = cli.data_binary {
        if let Some(path) = db.strip_prefix('@') {
            return Ok((Bytes::from(fs::read(path)?), true));
        }
        return Ok((Bytes::from(db.clone().into_bytes()), true));
    }
    if let Some(ref d) = cli.data {
        return Ok((Bytes::from(d.clone().into_bytes()), true));
    }
    Ok((Bytes::new(), false))
}

fn parse_user_headers(raw_headers: &[String]) -> anyhow::Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for raw in raw_headers {
        let (name_s, val_s) = raw
            .split_once(':')
            .with_context(|| format!("invalid -H header (missing ':'): {raw}"))?;
        let name = HeaderName::from_bytes(name_s.trim().as_bytes())?;
        let val = HeaderValue::from_str(val_s.trim())?;
        map.append(name, val);
    }
    Ok(map)
}

fn write_response(cli: &Cli, resp: &prototalpid_cli::HttpResponseData) -> anyhow::Result<()> {
    let mut out_buf = Vec::new();
    if cli.include || cli.head {
        writeln!(out_buf, "HTTP/1.1 {}", resp.status)?;
        for (k, v) in &resp.headers {
            if let Ok(vs) = v.to_str() {
                writeln!(out_buf, "{k}: {vs}")?;
            }
        }
        writeln!(out_buf)?;
    }
    if !cli.head {
        out_buf.extend_from_slice(&resp.body);
    }

    if let Some(ref path) = cli.output {
        fs::write(path, &out_buf)?;
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&out_buf)?;
        stdout.flush()?;
    }
    Ok(())
}
