#!/usr/bin/env python3
"""Opt-in Linux acceptance with an existing local Docker image and real libpq.

Runs installed binaries only, creates an isolated temporary container with no
published ports, and removes that container. No image/dependency is downloaded.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent


def accept(binary, core, image):
    docker = shutil.which('docker')
    if docker is None:
        raise RuntimeError('local Docker and an existing Postgres image are required')
    image_id = subprocess.check_output(
        [docker, 'image', 'inspect', image, '--format', '{{.Id}}'], text=True).strip()
    name = 'gateprobes-postgres-contract-' + uuid.uuid4().hex
    container = None
    try:
        container = subprocess.check_output([
            docker, 'run', '--detach', '--pull', 'never', '--name', name,
            '--network', 'none', '--label', 'task=GateHouse-24-live-contract',
            '--env', 'POSTGRES_USER=test', '--env', 'POSTGRES_PASSWORD=fixture',
            '--env', 'POSTGRES_DB=app_test', image_id,
        ], text=True).strip()
        deadline = time.monotonic() + 60
        while True:
            ready = subprocess.run([
                docker, 'exec', container, 'pg_isready', '-h', '127.0.0.1',
                '-p', '5432', '-U', 'test', '-d', 'app_test', '-t', '1',
            ], capture_output=True)
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('isolated Postgres TCP server did not become ready')
            time.sleep(0.25)
        spec = importlib.util.spec_from_file_location('installed_contract', HERE / 'contract.py')
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
        health = ('#!/bin/sh\nexec ' + shlex.quote(docker) +
                  ' exec --env PGHOST --env PGPORT --env PGDATABASE ' +
                  shlex.quote(container) + ' pg_isready "$@"\n')
        result = contract.accept(binary, core, health_program=health)
        result['health'] = 'real pg_isready with explicit host/port; TCP-ready isolated Docker server'
        result['image_id'] = image_id
        result['routing'] = 'closed target port blocks while the same server accepts TCP on 5432'
        return result
    finally:
        if container:
            subprocess.run([docker, 'rm', '--force', container], check=True, capture_output=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--core-binary', required=True, type=Path)
    parser.add_argument('--image', default='postgres:16-alpine')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = accept(args.binary, args.core_binary, args.image)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'cases': len(result['cases']),
                      'health': result['health'], 'image_id': result['image_id']}))
