//! Standalone distribution of our code. Rust/LLVM/Python stay external.
#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::{
    env,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
include!(env!("HARNESS_GATE_NATIVE_PAYLOAD"));

fn mode_matches(metadata: &fs::Metadata, mode: u32) -> bool {
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o777 == mode
    }
    #[cfg(windows)]
    {
        metadata.permissions().readonly() == (mode & 0o200 == 0)
    }
}

fn set_mode(file: &fs::File, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    let permissions = fs::Permissions::from_mode(mode);
    #[cfg(windows)]
    let permissions = {
        let mut permissions = file.metadata().map_err(|e| e.to_string())?.permissions();
        permissions.set_readonly(mode & 0o200 == 0);
        permissions
    };
    file.set_permissions(permissions).map_err(|e| e.to_string())
}

fn verify(root: &Path) -> Result<(), String> {
    for (name, bytes, mode) in PAYLOAD {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|e| format!("payload {name}: {e}"))?;
        if !metadata.is_file()
            || !mode_matches(&metadata, *mode)
            || fs::read(&path).map_err(|e| e.to_string())? != *bytes
        {
            return Err(format!("missing or modified plugin payload: {name}"));
        }
        let mut parent = path.parent().unwrap();
        loop {
            if fs::symlink_metadata(parent)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("plugin cache contains a symlink".into());
            }
            if parent == root {
                break;
            }
            parent = parent.parent().ok_or("invalid plugin cache path")?;
        }
    }
    fn inventory(root: &Path, path: &Path, actual: &mut Vec<String>) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                inventory(root, &entry.path(), actual)?;
            } else if kind.is_file() {
                actual.push(
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            } else {
                return Err("nonregular plugin cache member".into());
            }
        }
        Ok(())
    }
    let mut actual = Vec::new();
    inventory(root, root, &mut actual)?;
    actual.sort();
    let mut expected: Vec<_> = PAYLOAD.iter().map(|(n, _, _)| n.to_string()).collect();
    expected.sort();
    if actual != expected {
        return Err("plugin cache inventory differs".into());
    }
    Ok(())
}

fn payload() -> Result<PathBuf, String> {
    let cache = if let Some(path) = env::var_os("HARNESS_GATE_NATIVE_CACHE") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(path).join("harness-gate/native")
    } else if cfg!(windows) && env::var_os("LOCALAPPDATA").is_some() {
        PathBuf::from(env::var_os("LOCALAPPDATA").unwrap()).join("harness-gate/native")
    } else {
        PathBuf::from(
            env::var_os("HOME")
                .or_else(|| env::var_os("USERPROFILE"))
                .ok_or("HOME, LOCALAPPDATA or HARNESS_GATE_NATIVE_CACHE required")?,
        )
        .join(".cache/harness-gate/native")
    };
    if !cache.is_absolute() {
        return Err("plugin cache must be absolute".into());
    }
    fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let root = cache.join(PAYLOAD_ID);
    if !root.try_exists().map_err(|e| e.to_string())? {
        let staging = cache.join(format!(".{PAYLOAD_ID}-{}", std::process::id()));
        fs::create_dir(&staging).map_err(|e| format!("cannot stage plugin code: {e}"))?;
        for (name, bytes, mode) in PAYLOAD {
            let path = staging.join(name);
            fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(bytes).map_err(|e| e.to_string())?;
            set_mode(&file, *mode)?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        verify(&staging)?;
        if let Err(error) = fs::rename(&staging, &root) {
            if !root.exists() {
                return Err(format!("cannot activate plugin code: {error}"));
            }
            verify(&root)?;
            fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
        }
    }
    verify(&root)?;
    root.canonicalize().map_err(|e| e.to_string())
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args == [OsString::from("--version")] {
        println!("harness-gate-rust-collector {VERSION}");
        return Ok(ExitCode::SUCCESS);
    }
    if args == [OsString::from("--licenses")] {
        let (_, bytes, _) = PAYLOAD
            .iter()
            .find(|(name, _, _)| *name == "LICENSE")
            .ok_or("missing embedded licenses")?;
        std::io::stdout()
            .write_all(bytes)
            .map_err(|e| e.to_string())?;
        return Ok(ExitCode::SUCCESS);
    }
    let root = payload()?;
    let python = env::var_os("HARNESS_GATE_PYTHON").unwrap_or_else(|| {
        if cfg!(windows) {
            "python.exe".into()
        } else {
            "python3".into()
        }
    });
    let executable = env::current_exe().map_err(|e| e.to_string())?;
    let mut command = Command::new(python);
    command
        .args(["-I", "-S", "-B", "-X", "utf8"])
        .arg(root.join("app/native_external.py"))
        .args(&args)
        .env("HARNESS_GATE_NATIVE_ROOT", &root)
        .env("HARNESS_GATE_NATIVE_EXECUTABLE", executable)
        .env("HARNESS_GATE_NATIVE_VERSION", VERSION);
    #[cfg(unix)]
    return Err(format!(
        "cannot run external Python 3.12+ (set HARNESS_GATE_PYTHON): {}",
        command.exec()
    ));
    #[cfg(windows)]
    {
        let status = command.status().map_err(|error| {
            format!("cannot run external Python 3.12+ (set HARNESS_GATE_PYTHON): {error}")
        })?;
        Ok(ExitCode::from(if status.success() { 0 } else { 1 }))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("native collector: {error}");
            ExitCode::FAILURE
        }
    }
}
