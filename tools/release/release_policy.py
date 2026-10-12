#!/usr/bin/env python3
"""Fail-closed release eligibility checks for tag-triggered publication."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = 1
WORKFLOW_FILE = "ci.yml"
WORKFLOW_PATH = f".github/workflows/{WORKFLOW_FILE}"
REQUIRED_AGGREGATE = "Required Quality Aggregate"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40,64}$")
SEMVER_PATTERN = re.compile(
    r"^v(?P<version>"
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r")$"
)


class PolicyError(RuntimeError):
    """A release eligibility invariant was not satisfied."""


def version_from_tag(tag: str, prefix: str = "v") -> str:
    if prefix not in ("v", "rust-collector-v") or not tag.startswith(prefix):
        raise PolicyError(f"release tag must use the selected prefix {prefix!r}: {tag!r}")
    match = SEMVER_PATTERN.fullmatch("v" + tag[len(prefix):])
    if match is None:
        raise PolicyError(f"release tag must be exact SemVer with a {prefix} prefix: {tag!r}")
    return match.group("version")


def manifest_version(path: Path) -> str:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        version = document["package"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise PolicyError(f"cannot read package version from {path}: {exc}") from exc
    if not isinstance(version, str):
        raise PolicyError(f"package version in {path} must be a string")
    return version


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=check,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise PolicyError(f"git {' '.join(args)} failed{suffix}") from exc


def _resolve_commit(repo: Path, revision: str, label: str) -> str:
    result = _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    resolved = result.stdout.strip().lower()
    if COMMIT_PATTERN.fullmatch(resolved) is None:
        raise PolicyError(f"{label} did not resolve to a commit: {revision!r}")
    return resolved


def verify_git_state(repo: Path, tag: str, commit: str, main_ref: str) -> str:
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise PolicyError("release commit must be a full hexadecimal object ID")
    commit_oid = _resolve_commit(repo, commit, "release commit")
    tag_oid = _resolve_commit(repo, f"refs/tags/{tag}", "release tag")
    if tag_oid != commit_oid:
        raise PolicyError(
            f"release tag {tag} resolves to {tag_oid}, not requested commit {commit_oid}"
        )
    _resolve_commit(repo, main_ref, "protected main reference")
    ancestry = _git(
        repo,
        "merge-base",
        "--is-ancestor",
        commit_oid,
        main_ref,
        check=False,
    )
    if ancestry.returncode == 1:
        raise PolicyError(
            f"release commit {commit_oid} is not reachable from protected main reference {main_ref}"
        )
    if ancestry.returncode != 0:
        detail = (ancestry.stderr or ancestry.stdout or "").strip()
        raise PolicyError(f"cannot verify release ancestry: {detail or 'git failed'}")
    return commit_oid


class GitHubClient:
    def __init__(self, api_url: str, repository: str, token: str) -> None:
        if REPOSITORY_PATTERN.fullmatch(repository) is None:
            raise PolicyError(f"invalid GitHub repository identity: {repository!r}")
        if not token:
            raise PolicyError("GH_TOKEN is required to verify the protected main CI run")
        self.api_url = api_url.rstrip("/")
        self.repository = repository
        self.token = token

    def get_json(
        self, path: str, query: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "harness-gate-release-policy",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise PolicyError(f"GitHub API request failed for {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"GitHub API returned malformed JSON for {path}") from exc
        if not isinstance(payload, dict):
            raise PolicyError(f"GitHub API returned an unexpected payload for {path}")
        return payload


def select_eligible_run(
    payload: Mapping[str, Any],
    commit: str,
    main_branch: str,
    workflow_path: str = WORKFLOW_PATH,
) -> dict[str, Any]:
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise PolicyError("GitHub workflow-runs response is missing workflow_runs")
    eligible: list[dict[str, Any]] = []
    for candidate in runs:
        if not isinstance(candidate, dict):
            continue
        if (
            candidate.get("event") == "push"
            and candidate.get("head_branch") == main_branch
            and str(candidate.get("head_sha", "")).lower() == commit.lower()
            and candidate.get("path") == workflow_path
            and candidate.get("status") == "completed"
            and candidate.get("conclusion") == "success"
            and isinstance(candidate.get("id"), int)
            and not isinstance(candidate.get("id"), bool)
        ):
            eligible.append(candidate)
    if not eligible:
        raise PolicyError(
            f"no successful {workflow_path} push run exists on {main_branch} for {commit}"
        )
    return max(
        eligible,
        key=lambda run: (int(run.get("run_attempt", 0)), int(run["id"])),
    )


def require_aggregate_job(payload: Mapping[str, Any]) -> dict[str, Any]:
    jobs = payload.get("jobs")
    if not isinstance(jobs, list):
        raise PolicyError("GitHub jobs response is missing jobs")
    matches = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("name") == REQUIRED_AGGREGATE
    ]
    if len(matches) != 1:
        raise PolicyError(
            f"CI run must contain exactly one {REQUIRED_AGGREGATE!r} job"
        )
    job = matches[0]
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        raise PolicyError(f"{REQUIRED_AGGREGATE} did not complete successfully")
    return job


def verify_ci_run(
    client: GitHubClient,
    commit: str,
    main_branch: str,
) -> dict[str, Any]:
    workflow = urllib.parse.quote(WORKFLOW_FILE, safe="")
    runs_path = (
        f"/repos/{client.repository}/actions/workflows/{workflow}/runs"
    )
    runs = client.get_json(
        runs_path,
        {
            "branch": main_branch,
            "event": "push",
            "head_sha": commit,
            "status": "success",
            "per_page": "100",
        },
    )
    run = select_eligible_run(runs, commit, main_branch)
    run_id = int(run["id"])
    jobs = client.get_json(
        f"/repos/{client.repository}/actions/runs/{run_id}/jobs",
        {"filter": "latest", "per_page": "100"},
    )
    aggregate = require_aggregate_job(jobs)
    return {
        "workflow": WORKFLOW_PATH,
        "run_id": run_id,
        "run_attempt": int(run.get("run_attempt", 1)),
        "run_url": str(run.get("html_url", "")),
        "aggregate_job": REQUIRED_AGGREGATE,
        "aggregate_job_id": aggregate.get("id"),
        "aggregate_job_url": str(aggregate.get("html_url", "")),
    }


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify(args: argparse.Namespace) -> dict[str, Any]:
    version = version_from_tag(args.tag, args.tag_prefix)
    package_version = manifest_version(args.manifest)
    if version != package_version:
        raise PolicyError(
            f"release tag version {version} does not match package version {package_version}"
        )
    commit = verify_git_state(args.repo, args.tag, args.commit, args.main_ref)
    token = os.environ.get(args.token_env, "")
    client = GitHubClient(args.api_url, args.repository, token)
    ci = verify_ci_run(client, commit, args.main_branch)
    evidence: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": args.repository,
        "tag": args.tag,
        "version": version,
        "commit": commit,
        "protected_main": {
            "branch": args.main_branch,
            "ref": args.main_ref,
        },
        "ci": ci,
        "status": "pass",
    }
    if args.output is not None:
        _atomic_write_json(args.output, evidence)
    return evidence


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subcommands = root.add_subparsers(dest="command", required=True)
    command = subcommands.add_parser("verify", help="verify a tag is eligible to publish")
    command.add_argument("--tag", required=True)
    command.add_argument("--tag-prefix", choices=("v", "rust-collector-v"), default="v")
    command.add_argument("--commit", required=True)
    command.add_argument("--repository", required=True)
    command.add_argument("--repo", type=Path, default=Path("."))
    command.add_argument("--manifest", type=Path, required=True)
    command.add_argument("--main-branch", default="main")
    command.add_argument("--main-ref", default="refs/remotes/origin/main")
    command.add_argument("--api-url", default="https://api.github.com")
    command.add_argument("--token-env", default="GH_TOKEN")
    command.add_argument("--output", type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        evidence = verify(args)
    except PolicyError as exc:
        print(f"release policy error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
