#![cfg(target_os = "linux")]
use std::{
    io::Write,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
#[test]
fn missing_protected_descriptors_exit_cleanly_without_output() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-lifecycle"));
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::close(3);
            libc::close(4);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"{}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
#[test]
fn oversized_stdin_is_rejected_without_output() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-lifecycle"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b' '; 65_537])
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
