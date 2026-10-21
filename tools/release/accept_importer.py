"""Exercise an extracted importer with fixed downloaded Core/runtime inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def accept(bundle, core, assets):
    bundle, core, assets = bundle.resolve(), core.resolve(), assets.resolve()
    pin = json.loads((bundle / 'plugins/runtime-importer/core-pin.json').read_text())
    if digest(core) != pin['sha256'] or pin['version'] != '0.8.0':
        raise ValueError('acceptance Core pin mismatch')
    with tempfile.TemporaryDirectory(prefix='importer-accept-', dir=Path.home()) as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        reviewed = bundle / 'tools/runtime_import/release-pin.json'
        local_pin = root / 'runtime-pin.json'
        local_pin.write_bytes(reviewed.read_bytes()); local_pin.chmod(0o600)
        runtime = json.loads(local_pin.read_bytes())
        destination = root / 'installed'
        env = dict(os.environ, PYTHONPATH='', HOME=str(root))
        command = ['python3', '-I', '-B', str(bundle / 'tools/runtime_import/install.py'), '--pin', str(local_pin), '--assets', str(assets), '--destination', str(destination)]
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=30)
        if result.returncode or result.stderr or not destination.is_dir():
            raise ValueError('extracted importer installation failed')
        descriptor = destination / 'installation.json'
        exe = destination / 'gateprobes-docker-runtime'
        value = json.loads(descriptor.read_bytes())
        if value != {'schema':'gate-runtime-installation/v1','repository':runtime['repository'],'tag':runtime['tag'],'source_commit':runtime['source_commit'],'archive_sha256':runtime['archive_sha256'],'executable':{'path':str(exe),'sha256':runtime['executable_sha256'],'version':runtime['version']}}:
            raise ValueError('installed descriptor differs')
        if digest(exe) != runtime['executable_sha256']:
            raise ValueError('installed executable differs')
        for member in destination.iterdir():
            if stat.S_IMODE(member.stat().st_mode) != (0o500 if member == exe else 0o400):
                raise ValueError('installed mode differs')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            sock = root / 'fake.sock'
            listener.bind(str(sock)); listener.listen(1); listener.setblocking(False); sock.chmod(0o600)
            config = {'schema':'gate-runtime-engine-config/v2','engine':'docker','transport':'unix-http','socket_path':str(sock),'socket_uid':os.geteuid(),'principal_uid':os.geteuid(),'rootless':False,'api_version':'1.47','server_version':'27.0.1','daemon_id':'fake-daemon','scope':'acceptance'}
            cp=root/'config.json'; cp.write_text(json.dumps(config)); cp.chmod(0o600)
            binding={k:v for k,v in config.items() if k!='schema'}
            binding.update(protocol='gate-runtime/v2',adapter_sha256=digest(exe),adapter_version=runtime['version'],invocation='accept',operation_key='op',generation='gen',adapter_config_sha256=digest(cp))
            expected=root/'expected.json'; expected.write_text(json.dumps({'binding':binding,'operation':'capabilities'})); expected.chmod(0o600)
            host={'schema':'gate-runtime-host/installed-v1','installation':{'path':str(descriptor),'sha256':digest(descriptor),'schema':'gate-runtime-installation/v1'},'executable':value['executable'],'config':{'path':str(cp),'sha256':digest(cp),'schema':'gate-runtime-engine-config/v2'},'expected':{'path':str(expected),'sha256':digest(expected),'schema':'gate-runtime/v2'},'cwd':str(root),'timeout_ms':5000}
            hp=root/'host.json'; hp.write_text(json.dumps(host)); hp.chmod(0o600)
            probe=[str(core),'adapter','runtime-probe-installed','--request',str(expected),'--trusted-host',str(hp)]
            def run_probe(success):
                response=subprocess.run(probe,cwd=root,env=env,capture_output=True,timeout=15)
                if success:
                    if response.returncode or response.stderr:
                        raise ValueError('installed probe failed')
                    parsed=json.loads(response.stdout)
                    if parsed['binding']!=binding or parsed['operation']!='capabilities' or parsed['observations'] is not None or parsed['outcome']!={'capabilities':{'supported':['inspect']}}:
                        raise ValueError('installed probe facts differ')
                elif response.returncode==0 or response.stdout:
                    raise ValueError('tampered installation accepted')
                try:
                    connection,_=listener.accept();connection.close()
                except BlockingIOError:
                    return
                raise ValueError('capabilities connected to socket')
            run_probe(True)
            original=descriptor.read_bytes();descriptor.chmod(0o600);descriptor.write_bytes(original+b' ');run_probe(False)
            descriptor.write_bytes(original);descriptor.chmod(0o400)
            exe.chmod(0o700);exe.write_bytes(b'tampered');exe.chmod(0o500);run_probe(False)
        runtime['archive_sha256']='0'*64;local_pin.write_text(json.dumps(runtime))
        bad=root/'bad-pin';command[-1]=str(bad)
        result=subprocess.run(command,cwd=root,env=env,capture_output=True,timeout=30)
        if result.returncode==0 or bad.exists():
            raise ValueError('tampered pin accepted')
    return {'passed':True,'core_sha256':digest(core),'runtime_tag':'docker-runtime-v0.1.1','cases':4,'scope':'direct installed path; fake socket only; no zero-spawn claim'}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--core',type=Path,required=True)
    parser.add_argument('--assets',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(accept(args.bundle,args.core,args.assets),sort_keys=True))
