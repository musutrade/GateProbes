//! Postgres facts only. Core owns requiredness, execution and final authority.
use anyhow::{bail, Context, Result};
use std::net::IpAddr;
use url::{Host, Url};
pub const ALLOW_REMOTE_TEST_DATABASE_ENV: &str = "HARNESS_GATE_ALLOW_REMOTE_TEST_DATABASE";
const DEFAULT_PORT: u16 = 5432;
#[derive(Debug, PartialEq, Eq)]
struct PostgresTarget {
    host: String,
    port: u16,
    database: String,
    loopback: bool,
}

fn parse_postgres_target(value: &str) -> Result<PostgresTarget> {
    let url = Url::parse(value).context("test database URL must be a valid URL")?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        bail!("test database URL must use the postgres or postgresql scheme");
    }
    if url.query().is_some() || url.fragment().is_some() || url.path().contains('%') {
        bail!("query overrides, fragments and encoded database names are not supported");
    }
    let (host, loopback) = match url
        .host()
        .context("test database URL must include a host")?
    {
        Host::Domain(host) => {
            let normalized = host.to_ascii_lowercase();
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            (normalized, loopback)
        }
        Host::Ipv4(address) => (address.to_string(), IpAddr::V4(address).is_loopback()),
        Host::Ipv6(address) => (address.to_string(), IpAddr::V6(address).is_loopback()),
    };
    let mut segments = url
        .path_segments()
        .context("test database URL must include a database name")?;
    let database = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .context("test database URL must include a database name")?
        .to_ascii_lowercase();
    if segments.any(|segment| !segment.is_empty()) {
        bail!("test database URL must contain exactly one database name");
    }
    Ok(PostgresTarget {
        host,
        port: url.port().unwrap_or(DEFAULT_PORT),
        database,
        loopback,
    })
}

pub fn validate_isolated_postgres_url(
    value: &str,
    production_url: Option<&str>,
    allow_remote: bool,
) -> Result<()> {
    let target = parse_postgres_target(value)?;
    if !target.database.ends_with("_test") && !target.database.ends_with("-test") {
        bail!("test database name must end with _test or -test");
    }
    if !target.loopback && !allow_remote {
        bail!(
            "remote test databases require {ALLOW_REMOTE_TEST_DATABASE_ENV}=1 after isolation is verified"
        );
    }
    if let Some(production_url) = production_url {
        if value == production_url {
            bail!("TEST_DATABASE_URL must not equal DATABASE_URL");
        }
        if let Ok(production) = parse_postgres_target(production_url) {
            let same_host =
                target.host == production.host || (target.loopback && production.loopback);
            if same_host && target.port == production.port && target.database == production.database
            {
                bail!("TEST_DATABASE_URL must not target the DATABASE_URL database");
            }
        }
    }
    Ok(())
}

/// Explicit libpq address fields; a URI in PGDATABASE is only a database default.
/// Readiness concerns the selected server, not authentication or SQL execution.
pub fn health_target(value: &str) -> Result<(String, u16, String)> {
    let target = parse_postgres_target(value)?;
    Ok((target.host, target.port, target.database))
}

#[cfg(test)]
mod tests {
    use super::{validate_isolated_postgres_url, ALLOW_REMOTE_TEST_DATABASE_ENV};

    #[test]
    fn health_target_keeps_the_explicit_address_and_default_port() {
        assert_eq!(
            super::health_target("postgres://test:private@127.0.0.1:1/app_test").unwrap(),
            ("127.0.0.1".into(), 1, "app_test".into())
        );
        assert_eq!(
            super::health_target("postgres://test:private@[::1]/app_test").unwrap(),
            ("::1".into(), 5432, "app_test".into())
        );
    }

    #[test]
    fn accepts_an_isolated_loopback_database() {
        let result = validate_isolated_postgres_url(
            "postgres://tester:secret@127.0.0.1:5432/arc_admin_test",
            Some("postgres://developer:secret@localhost:5432/arc_admin"),
            false,
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn accepts_an_ipv6_loopback_database() {
        assert!(validate_isolated_postgres_url(
            "postgres://tester:secret@[::1]:5432/arc_admin_test",
            None,
            false,
        )
        .is_ok());
    }

    #[test]
    fn rejects_a_database_without_a_test_suffix() {
        let error = validate_isolated_postgres_url(
            "postgres://tester:secret@localhost/arc_admin",
            None,
            false,
        )
        .expect_err("production-like database name must fail");
        assert!(error.to_string().contains("must end with"));
    }

    #[test]
    fn rejects_a_remote_database_without_an_explicit_override() {
        let error = validate_isolated_postgres_url(
            "postgresql://tester:secret@test-db.example.com/arc_admin_test",
            None,
            false,
        )
        .expect_err("remote database must fail closed");
        assert!(error.to_string().contains(ALLOW_REMOTE_TEST_DATABASE_ENV));
    }

    #[test]
    fn accepts_an_explicitly_allowed_remote_test_database() {
        assert!(validate_isolated_postgres_url(
            "postgres://tester:secret@test-db.example.com/arc-admin-test",
            None,
            true,
        )
        .is_ok());
    }

    #[test]
    fn rejects_the_configured_runtime_database() {
        let error = validate_isolated_postgres_url(
            "postgres://tester:secret@127.0.0.1:5432/arc_admin_test",
            Some("postgresql://runtime:secret@localhost:5432/arc_admin_test"),
            false,
        )
        .expect_err("same database target must fail");
        assert!(
            error.to_string().contains("DATABASE_URL database"),
            "{error:?}"
        );
    }
}
