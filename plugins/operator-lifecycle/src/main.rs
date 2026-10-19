//! Explicit operator lifecycle; no quality evaluation or publication controller.
mod canary;
mod hooks;
use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Manage exact thin hooks; configuration inspection is read-only.
    Hooks {
        #[arg(long)]
        core: PathBuf,
        #[arg(long)]
        core_sha256: String,
        #[command(subcommand)]
        action: hooks::HookAction,
    },
    /// Record an external migration choice; never changes Core execution.
    Canary {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        slice: String,
    },
    /// Record external rollback; never modifies Core or installed toolchains.
    Rollback {
        #[arg(long)]
        state: PathBuf,
    },
}
fn main() {
    match run(Cli::parse()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("operator operation failed: {error:#}");
            std::process::exit(1);
        }
    }
}
fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Action::Hooks {
            core,
            core_sha256,
            action,
        } => {
            ensure!(
                core.is_absolute() && core.is_file(),
                "Core must be an absolute executable path"
            );
            ensure!(
                format!("{:x}", Sha256::digest(fs::read(&core)?)) == core_sha256,
                "Core digest does not match operator pin"
            );
            hooks::run(&cli.project_root, &core, action)
        }
        Action::Canary { state, slice } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&canary::set_canary(&state, &slice)?)?
            );
            Ok(true)
        }
        Action::Rollback { state } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&canary::rollback(&state)?)?
            );
            Ok(true)
        }
    }
}
fn capture(program: &Path, args: &[&str], root: &Path) -> Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .context("start read-only inspection")?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(30) {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("read-only inspection timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    use std::io::{Read, Seek};
    let read = |mut file: fs::File| -> Result<Vec<u8>> {
        ensure!(
            file.metadata()?.len() <= 8 * 1024 * 1024,
            "inspection output too large"
        );
        file.rewind()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    Ok(Output {
        status,
        stdout: read(stdout)?,
        stderr: read(stderr)?,
    })
}
