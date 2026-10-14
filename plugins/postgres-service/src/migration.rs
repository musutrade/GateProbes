use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    version: u32,
    paths: Paths,
    doctor: Doctor,
    database: Database,
    scope: Value,
    steps: Vec<Step>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Paths {
    backend: String,
    frontend: String,
    reports: String,
    tool_manifest: String,
    audit_config: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doctor {
    required_commands: Vec<String>,
    node_version_file: String,
    hooks_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    image: String,
    startup_timeout_secs: u64,
    container_port: u16,
    user: String,
    password: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    id: String,
    label: String,
    component: String,
    profiles: BTreeSet<String>,
    program: String,
    args: Vec<String>,
    cwd: String,
    log: String,
    timeout_secs: u64,
    #[serde(default)]
    timeout_env: Option<String>,
    #[serde(default)]
    parser: Option<String>,
    #[serde(default)]
    requires_test_database: bool,
}

fn recipe(db: &Database) -> Value {
    json!({"kind":"docker","runtime":"docker","image":db.image,
        "image_env":"HARNESS_GATE_POSTGRES_IMAGE","external_env":"TEST_DATABASE_URL",
        "inject_env":"TEST_DATABASE_URL","startup_timeout_secs":db.startup_timeout_secs,
        "timeout_env":"HARNESS_GATE_DATABASE_TIMEOUT_SECS","container_port":db.container_port,
        "environment":{"POSTGRES_USER":db.user,"POSTGRES_PASSWORD":db.password,"POSTGRES_DB":db.name},
        "healthcheck":["pg_isready","-U",db.user,"-d",db.name],
        "connection":format!("postgres://{}:{}@127.0.0.1:{{host_port}}/{}",db.user,db.password,db.name)})
}

fn doctor_check(id: &str, kind: Value, required: bool) -> Value {
    let mut result = json!({"id":id,"label":id,"required":required,"timeout_secs":15});
    result
        .as_object_mut()
        .unwrap()
        .extend(kind.as_object().unwrap().clone());
    result
}

fn legacy(source: &str, project: &str) -> Result<Value> {
    let old: Legacy = toml::from_str(source).context("unsupported legacy configuration")?;
    if old.version != 1 {
        bail!("not v1");
    }
    // Credential/template delimiters were previously interpolated literally.
    // Refuse unsafe values rather than changing their interpretation.
    for value in [
        &old.database.user,
        &old.database.password,
        &old.database.name,
    ] {
        if value.contains([':', '/', '@', '{', '}', '%', '?', '#']) {
            bail!("unsafe legacy connection field");
        }
    }
    let mut aliases = BTreeMap::new();
    aliases.insert(
        "backend",
        json!({"path":old.paths.backend,"env":"HARNESS_GATE_BACKEND"}),
    );
    aliases.insert(
        "frontend",
        json!({"path":old.paths.frontend,"env":"HARNESS_GATE_FRONTEND"}),
    );
    aliases.insert(
        "tool_manifest",
        json!({"path":old.paths.tool_manifest,"env":"HARNESS_GATE_TOOL_MANIFEST"}),
    );
    let mut required = Vec::new();
    let steps: Vec<Value> = old.steps.into_iter().map(|s| {
        required.push(s.id.clone());
        let mut step = json!({"id":s.id,"label":s.label,"component":s.component,"profiles":s.profiles,
            "program":s.program,"args":s.args,"cwd":s.cwd,"log":s.log,"timeout_secs":s.timeout_secs,
            "services":if s.requires_test_database {vec!["test-postgres"]} else {vec![]},
            "remove_env":if s.requires_test_database {vec!["DATABASE_URL"]} else {vec![]},
            "depends_on":[],"input":"snapshot"});
        if let Some(v) = s.timeout_env { step["timeout_env"] = json!(v); }
        if let Some(v) = s.parser { step["parser"] = json!(v); }
        step
    }).collect();
    let mut checks: Vec<Value> = old
        .doctor
        .required_commands
        .into_iter()
        .map(|p| {
            doctor_check(
                &format!("command.{p}"),
                json!({"kind":"command","program":p,"args":["--version"]}),
                true,
            )
        })
        .collect();
    checks.extend([
        doctor_check("frontend.dependencies", json!({"kind":"path","path":"{frontend}/node_modules","path_type":"directory","path_scope":"repository"}),true),
        doctor_check("runtime.database",json!({"kind":"env-or-file","env":"DATABASE_URL","path":"{backend}/.env","contains":"DATABASE_URL=","path_scope":"repository"}),true),
        doctor_check("backend.migrations",json!({"kind":"glob","pattern":"{backend}/migrations/*.sql"}),true),
        doctor_check("git.hooks",json!({"kind":"git-config","key":"core.hooksPath","expected":old.doctor.hooks_path}),false),
        doctor_check("node.version",json!({"kind":"version","program":"node","args":["--version"],"path":format!("{{root}}/{}",old.doctor.node_version_file),"trim_prefix":"v","path_scope":"repository"}),true),
        doctor_check("git.remotes",json!({"kind":"git-remotes"}),true),
        // The required service check must also block doctor; old optionality is upgraded explicitly.
        doctor_check("test.database",json!({"kind":"service","service":"test-postgres"}),true),
    ]);
    Ok(
        json!({"version":2,"project":{"name":project,"default_profile":"full","hook_profile":"hook"},
        "paths":{"reports":old.paths.reports,"audit_config":old.paths.audit_config,"secrets_config":".harness-gate/secrets.toml","aliases":aliases},
        "policy":{"required_steps":required,"waivers":[]},"doctor":{"checks":checks},
        "services":{"test-postgres":recipe(&old.database)},
        "parsers":{"rust":{"kind":"regex","patterns":[r"(?m)^running ([0-9]+) tests?$"],"capture":1,"minimum":1},
            "angular":{"kind":"regex","patterns":[r"Tests\s+([0-9]+) passed"],"capture":1,"minimum":1}},
        "scope":old.scope,"steps":steps}),
    )
}

fn binding(executable: &Path) -> Result<Value> {
    Ok(
        json!({"executable":executable.to_str().context("non UTF-8 installation")?,
        "sha256":format!("{:x}",Sha256::digest(std::fs::read(executable)?)),
        "protocol":"gate-service-check/v1","plugin":"gateprobes-postgres",
        "version":env!("CARGO_PKG_VERSION"),"timeout_secs":15,
        "pass_env":["DATABASE_URL","HARNESS_GATE_ALLOW_REMOTE_TEST_DATABASE","PATH","SYSTEMROOT"]}),
    )
}

fn convert(source: &str, project: &str, executable: &Path) -> Result<Value> {
    let raw: toml::Value = toml::from_str(source)?;
    let mut config = match raw.get("version").and_then(toml::Value::as_integer) {
        Some(1) => legacy(source, project)?,
        Some(2) => serde_json::to_value(raw)?,
        _ => bail!("unsupported flow version"),
    };
    let mut selected = Vec::new();
    if config["service_checks"].is_null() {
        config["service_checks"] = json!({});
    }
    for (id, service) in config["services"]
        .as_object_mut()
        .context("services required")?
    {
        if let Some(policy) = service
            .as_object_mut()
            .unwrap()
            .remove("external_value_policy")
        {
            match policy.as_str() {
                Some("isolated-postgres") => selected.push(id.clone()),
                Some("none") => {}
                _ => bail!("unknown legacy external policy"),
            }
        } else if id == "test-postgres" && source.contains("version = 1") {
            selected.push(id.clone());
        }
    }
    // TOML spacing is irrelevant to deciding v1 mapping.
    if config["services"]["test-postgres"].is_object() && raw_version(source)? == 1 {
        selected = vec!["test-postgres".into()];
    }
    for id in selected {
        let checks = config["service_checks"]
            .as_object_mut()
            .context("service_checks must be a table")?;
        if checks.contains_key(&id) {
            bail!("refusing to replace existing required checks");
        }
        checks.insert(id.clone(), json!([binding(executable)?]));
        if config["doctor"]["checks"].is_null() {
            config["doctor"]["checks"] = json!([]);
        }
        let doctors = config["doctor"]["checks"]
            .as_array_mut()
            .context("doctor checks must be an array")?;
        for check in doctors
            .iter_mut()
            .filter(|c| c["kind"] == "service" && c["service"] == id)
        {
            check["required"] = json!(true);
        }
        if !doctors
            .iter()
            .any(|c| c["kind"] == "service" && c["service"] == id && c["required"] == true)
        {
            doctors.push(doctor_check(
                &format!("service.{id}"),
                json!({"kind":"service","service":id}),
                true,
            ));
        }
    }
    Ok(config)
}
fn raw_version(source: &str) -> Result<i64> {
    Ok(toml::from_str::<toml::Value>(source)?
        .get("version")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0))
}

pub fn run(args: &[String]) -> Result<()> {
    let mut options = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2
            || !matches!(pair[0].as_str(), "--input" | "--output" | "--project")
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            bail!("usage: migrate --input <PATH> --output <NEW_PATH> --project <NAME>");
        }
    }
    let input = options.get("--input").context("input required")?;
    let output = options.get("--output").context("output required")?;
    let project = options.get("--project").context("project required")?;
    let source = std::fs::read_to_string(input)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let config = convert(&source, project, &executable)?;
    let value = toml::Value::try_from(config)?;
    let bytes = toml::to_string_pretty(&value)?;
    // create_new refuses overwrite, including the source and symlinks.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(bytes.as_bytes())?;
    file.sync_all()?;
    println!("Migration written; run harness-gate config check before adoption. Source retained.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_and_policy_migration_bind_the_installed_artifact() {
        let exe = std::env::current_exe().unwrap();
        let source = include_str!("../fixtures/v1-flow.toml");
        let migrated = convert(source, "fixture", &exe).unwrap();
        assert_eq!(
            migrated["services"]["test-postgres"]["healthcheck"][0],
            "pg_isready"
        );
        assert_eq!(
            migrated["service_checks"]["test-postgres"][0]["protocol"],
            "gate-service-check/v1"
        );
        assert_eq!(migrated["policy"]["required_steps"][0], "app.check");
        assert!(migrated["services"]["test-postgres"]
            .get("external_value_policy")
            .is_none());
        assert!(migrated["doctor"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "service" && c["required"] == true));
        let source = include_str!("../fixtures/v2-flow.toml");
        let migrated = convert(source, "fixture", &exe).unwrap();
        assert_eq!(
            migrated["service_checks"]["test-postgres"][0]["sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert!(convert(
            &source.replace("isolated-postgres", "unknown"),
            "fixture",
            &exe
        )
        .is_err());
        let serialized = toml::to_string(&toml::Value::try_from(migrated).unwrap()).unwrap();
        assert!(convert(&serialized, "fixture", &exe).is_ok());
    }
}
