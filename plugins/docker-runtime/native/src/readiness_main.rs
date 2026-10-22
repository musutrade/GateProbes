//! Dedicated v3 entry. The v2 binary keeps its original input contract.
fn main() {
    #[cfg(target_os = "linux")]
    let result = gateprobes_docker_runtime::readiness::execute();
    #[cfg(not(target_os = "linux"))]
    let result: Result<Vec<u8>, &'static str> = Err("v3 runtime requires Linux");
    use std::io::Write;
    match result {
        Ok(bytes) => {
            if std::io::stdout()
                .write_all(&bytes)
                .and_then(|_| std::io::stdout().flush())
                .is_err()
            {
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("runtime v3 input or execution rejected");
            std::process::exit(1);
        }
    }
}
