mod migration;
use anyhow::{bail, Result};
use std::process::{Command, Stdio};
const PROTOCOL: &str = "gate-service-check/v1";

fn check() -> Result<()> {
    if std::env::var("GATE_CHECK_PROTOCOL").as_deref() != Ok(PROTOCOL) {
        bail!("unsupported service check protocol");
    }
    let mode = std::env::var("GATE_CHECK_MODE")?;
    match mode.as_str() {
        "external" => {
            let value = std::env::var("GATE_CHECK_VALUE")?;
            let production = std::env::var("DATABASE_URL").ok();
            let allow_remote = std::env::var(gateprobes_postgres::ALLOW_REMOTE_TEST_DATABASE_ENV)
                .is_ok_and(|flag| matches!(flag.as_str(), "1" | "true"));
            gateprobes_postgres::validate_isolated_postgres_url(
                &value,
                production.as_deref(),
                allow_remote,
            )?;
            // libpq reads PGDATABASE. Credentials never appear in argv or output.
            let status = Command::new("pg_isready")
                .env("PGDATABASE", value)
                .args(["-t", "5"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if !status.success() {
                bail!("Postgres health check failed");
            }
        }
        "managed" => { /* Health recipe executes inside the Core-owned container. */ }
        _ => bail!("unsupported service check mode"),
    }
    println!(
        "{}",
        serde_json::json!({"protocol":PROTOCOL,"plugin":"gateprobes-postgres",
        "version":env!("CARGO_PKG_VERSION"),"mode":mode,"success":true})
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("migrate") {
        migration::run(&args[1..])
    } else if args == ["--version"] {
        println!("gateprobes-postgres {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else if args.is_empty() {
        check()
    } else {
        bail_result()
    };
    if result.is_err() {
        // Library errors may contain URL parser details. Never emit user input.
        eprintln!("gateprobes-postgres failed; check protocol, isolated URL, pg_isready and migration arguments");
        std::process::exit(1);
    }
}
fn bail_result() -> Result<()> {
    bail!("unsupported arguments")
}
