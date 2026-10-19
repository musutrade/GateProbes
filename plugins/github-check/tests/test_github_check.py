"""Acceptance tests for the independent existing-Check result consumer.

Every mapping/delivery test consumes a real saved Core report produced by the
shipped CLI and validated through the pinned `report-verify` path; only the
GitHub Check transport is fake. No live GitHub writes are permitted.
"""
import atexit
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

consumer = common.consumer()


def cleanup():
    for root, _ in common.SHARED.values():
        shutil.rmtree(root, ignore_errors=True)


atexit.register(cleanup)


def frozen(verified):
    return copy.deepcopy(verified)


class RealCoreAcceptance(unittest.TestCase):
    """Mapping uses real Core decisions; only the API transport is simulated."""

    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('pass')

    def test_real_pass_result_is_verified_saved_evidence(self):
        result = self.verified['result']
        self.assertEqual(self.verified['historical_integrity'], 'verified')
        self.assertEqual(self.verified['current_applicability'], 'not_evaluated')
        self.assertEqual(result['status'], 'PASS')
        self.assertIs(result['passed'], True)
        self.assertIs(result['evidence_complete'], True)
        self.assertEqual(result['quality']['phase'], 'complete')
        self.assertEqual(result['quality']['status'], 'pass')
        self.assertEqual(result['quality']['full_quality_status'], 'pass')
        self.assertIs(result['identities']['policy_binding_complete'], True)

    def test_approved_exact_result_maps_to_success_and_confirms_once(self):
        config = common.config_for(self.verified)
        payload = consumer.mapping(config, self.verified)
        self.assertEqual(payload['conclusion'], 'success')
        self.assertEqual(payload['status'], 'completed')
        self.assertEqual(payload['external_id'],
                         'gate-result:' + config['machine_sha256'] + ':1')
        api = common.FakeAPI(common.remote_for(config))
        state = Path(tempfile.mkdtemp(prefix='gatehouse-state-')) / 'state.db'
        first = consumer.deliver(config, payload, state, api)
        self.assertEqual([call[0] for call in api.calls], ['GET', 'PATCH'])
        self.assertEqual(first['conclusion'], 'success')
        again = consumer.deliver(config, payload, state, api)
        self.assertEqual(again['conclusion'], 'success')
        self.assertEqual([call[0] for call in api.calls], ['GET', 'PATCH'], 'confirmed duplicate must not mutate')
        newer = dict(config, generation=config['generation'] + 1)
        delivered = consumer.deliver(newer, consumer.mapping(newer, self.verified), state, api)
        self.assertEqual(delivered['external_id'],
                         'gate-result:' + config['machine_sha256'] + ':2')
        self.assertEqual([call[0] for call in api.calls], ['GET', 'PATCH', 'GET', 'PATCH'])
        stale = dict(config, generation=config['generation'] - 1)
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(stale, payload, state, api)
        self.assertIn('stale generation', str(raised.exception))

    def test_conflicting_duplicate_generation_rejected(self):
        config = common.config_for(self.verified)
        payload = consumer.mapping(config, self.verified)
        api = common.FakeAPI(common.remote_for(config))
        state = Path(tempfile.mkdtemp(prefix='gatehouse-state-')) / 'state.db'
        consumer.deliver(config, payload, state, api)
        conflicting = copy.deepcopy(payload)
        conflicting['name'] = 'gatehouse/other-name'
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(config, conflicting, state, api)
        self.assertIn('conflicting duplicate generation', str(raised.exception))
        self.assertEqual(len(api.calls), 2, 'conflict must fail before any remote call')

    def test_wrong_pins_and_identities_rejected_without_success(self):
        config = common.config_for(self.verified)
        for key, value in [
            ('machine_sha256', '0' * 64),
            ('manifest_sha256', '0' * 64),
            ('invocation_id', 'invocation-other'),
            ('source_identity', 'source-other'),
            ('configuration_digest', 'digest-other'),
            ('profile', 'hook'),
            ('verification_policy_identity', 'policy-other'),
            ('quality_policy_identity', 'quality-other'),
            ('runtime_bundle_digest', 'runtime-other'),
            ('current_use_review', 'pending'),
        ]:
            with self.assertRaises(consumer.Rejected, msg=key):
                consumer.mapping(dict(config, **{key: value}), self.verified)

    def test_target_validation_rejects_invalid_approval(self):
        config = common.config_for(self.verified)
        for key, value in [
            ('repository', 'not-a-repo'),
            ('target_sha', 'ABCDEF'),
            ('check_id', 0),
            ('app_id', -2),
            ('generation', 0),
            ('check_name', ''),
            ('check_name', 'x' * 101),
            ('expires_at', '2020-01-01T00:00:00+00:00'),
            ('expires_at', '2030-01-01T00:00:00'),
        ]:
            with self.assertRaises(consumer.Rejected, msg=key):
                consumer.mapping(dict(config, **{key: value}), self.verified)

    def test_unexecuted_status_and_incomplete_quality_cannot_succeed(self):
        skipped = frozen(self.verified)
        skipped['result']['status'] = 'SKIPPED'
        skipped['result']['passed'] = False
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.mapping(common.config_for(self.verified), skipped)
        self.assertIn('unexecuted result', str(raised.exception))
        # Core never marks a partial quality result as passed; the consumer
        # keeps the guard in depth even against an internally inconsistent copy.
        partial = frozen(self.verified)
        partial['result']['quality'] = dict(partial['result']['quality'],
                                            phase='configuration', status='blocked',
                                            full_quality_status='blocked')
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.mapping(common.config_for(self.verified), partial)
        self.assertIn('full quality result required', str(raised.exception))


class FailingRealCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('unsupported')

    def test_failing_quality_result_maps_to_failure(self):
        result = self.verified['result']
        self.assertEqual(result['status'], 'FAIL')
        self.assertIs(result['passed'], False)
        self.assertEqual(result['quality']['status'], 'fail')
        config = common.config_for(self.verified)
        payload = consumer.mapping(config, self.verified)
        self.assertEqual(payload['conclusion'], 'failure')
        api = common.FakeAPI(common.remote_for(config))
        state = Path(tempfile.mkdtemp(prefix='gatehouse-state-')) / 'state.db'
        confirmed = consumer.deliver(config, payload, state, api)
        self.assertEqual(confirmed['conclusion'], 'failure')


class TamperedEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('pass')

    def _mutated_index(self, mutate):
        config = common.config_for(self.verified)
        api = common.FakeAPI(common.remote_for(config))
        with tempfile.TemporaryDirectory(prefix='gatehouse-tamper-') as work:
            root = Path(work)
            shutil.copytree(self.root, root / 'copy')
            index = json.loads((root / 'copy/history.json').read_text())
            mutate(root / 'copy', index)
            index_path = root / 'copy/history.json'
            index_path.write_text(json.dumps(index))
            alt = dict(config)
            try:
                return consumer.saved_result(common.CORE, alt['verifier_sha256'], index_path), api
            except consumer.Rejected as error:
                return error, api

    def test_tampered_report_bytes_rejected(self):
        def mutate(root, _index):
            report = next(root.glob('.harness-gate/reports/invocations/*/test_result.json'))
            data = bytearray(report.read_bytes())
            data[0] = ord('[') if data[0] != ord('[') else ord('{')
            report.write_bytes(bytes(data))

        outcome, _ = self._mutated_index(mutate)
        self.assertIsInstance(outcome, consumer.Rejected)
        self.assertIn('rejected saved evidence', str(outcome))

    def test_wrong_machine_pin_rejected(self):
        def mutate(_root, index):
            index['samples'][0]['machine_sha256'] = 'f' * 64

        outcome, _ = self._mutated_index(mutate)
        self.assertIsInstance(outcome, consumer.Rejected)
        self.assertIn('rejected saved evidence', str(outcome))


class DeliveryFencing(unittest.TestCase):
    """Ambiguous or conflicting writes must never be reported as success."""

    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('pass')
        cls.config = common.config_for(cls.verified)
        cls.payload = consumer.mapping(cls.config, cls.verified)

    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix='gatehouse-state-')) / 'state.db'

    def _rows(self):
        import sqlite3
        with sqlite3.connect(self.state) as db:
            return db.execute('SELECT generation,phase FROM deliveries').fetchall()

    def test_ambiguous_patch_blocks_later_operations(self):
        api = common.FakeAPI(common.remote_for(self.config))
        api.patch_error = TimeoutError('simulated timeout')
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(self.config, self.payload, self.state, api)
        self.assertIn('API update unconfirmed', str(raised.exception))
        self.assertEqual(self._rows(), [(1, 'intent')])
        recovered = common.FakeAPI(common.remote_for(self.config))
        same = dict(self.config, generation=self.config['generation'] + 1)
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(same, self.payload, self.state, recovered)
        self.assertIn('uncertain prior API operation', str(raised.exception))
        self.assertEqual(recovered.calls, [], 'fence must reject before any new remote call')
        with self.assertRaises(consumer.Rejected):
            consumer.deliver(self.config, self.payload, self.state, recovered)
        self.assertEqual(self._rows(), [(1, 'intent')])

    def test_preflight_failure_leaves_no_fence(self):
        api = common.FakeAPI(common.remote_for(self.config))
        api.get_error = TimeoutError('simulated preflight timeout')
        with self.assertRaises(TimeoutError):
            consumer.deliver(self.config, self.payload, self.state, api)
        self.assertEqual(self._rows(), [])
        retry = common.FakeAPI(common.remote_for(self.config))
        confirmed = consumer.deliver(self.config, self.payload, self.state, retry)
        self.assertEqual(confirmed['conclusion'], 'success')
        self.assertEqual(self._rows(), [(1, 'confirmed')])

    def test_wrong_remote_identity_rejected_before_state(self):
        remote = common.remote_for(self.config)
        remote['head_sha'] = 'f' * 40
        api = common.FakeAPI(remote)
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(self.config, self.payload, self.state, api)
        self.assertIn('remote Check identity mismatch', str(raised.exception))
        self.assertEqual(self._rows(), [])
        self.assertEqual([call[0] for call in api.calls], ['GET'])

    def test_unconfirmed_patch_reply_keeps_fence(self):
        remote = common.remote_for(self.config)

        class LyingAPI(common.FakeAPI):
            def request(self, method, path, payload=None):
                if method == 'PATCH':
                    self.calls.append((method, path, payload))
                    return dict(self.remote, status='completed', conclusion='neutral',
                                external_id='gate-result:other:1')
                return super().request(method, path, payload)

        api = LyingAPI(remote)
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.deliver(self.config, self.payload, self.state, api)
        self.assertIn('API update unconfirmed', str(raised.exception))
        self.assertEqual(self._rows(), [(1, 'intent')])

    def test_withdrawal_delivers_platform_disapproval(self):
        config = dict(self.config, current_use_review='withdrawn',
                      withdrawal_reason='superseded by a later result')
        payload = consumer.withdrawal(config)
        self.assertEqual(payload['external_id'], 'gate-withdrawal:1')
        self.assertEqual(payload['conclusion'], 'failure')
        api = common.FakeAPI(common.remote_for(config))
        confirmed = consumer.deliver(config, payload, self.state, api)
        self.assertEqual(confirmed['conclusion'], 'failure')
        self.assertEqual(confirmed['external_id'], 'gate-withdrawal:1')
        self.assertEqual([call[0] for call in api.calls], ['GET', 'PATCH'])

    def test_withdrawal_rejects_incomplete_review(self):
        with self.assertRaises(consumer.Rejected):
            consumer.withdrawal(dict(self.config, current_use_review='approved-exact-result'))
        with self.assertRaises(consumer.Rejected):
            consumer.withdrawal(dict(self.config, current_use_review='withdrawn', withdrawal_reason=''))


class CredentialAndInputBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('pass')

    def test_core_subprocess_does_not_inherit_credentials(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-env-') as work:
            work = Path(work)
            dump = work / 'env.json'
            fake_core = work / 'core'
            (work / 'verified.json').write_text(json.dumps(self.verified))
            fake_core.write_text(
                '#!/usr/bin/env python3\n'
                'import json, os, sys\n'
                f'open({str(dump)!r}, "w").write(json.dumps(dict(os.environ)))\n'
                f'open({str(work / "verified.json")!r}, "r").read() and '
                f'sys.stdout.write(open({str(work / "verified.json")!r}).read())\n')
            fake_core.chmod(0o700)
            os.environ['GATEHOUSE_CHECK_TOKEN'] = 'secret-consumer-token'
            os.environ['GH_TOKEN'] = 'secret-gh-token'
            os.environ['GITHUB_TOKEN'] = 'secret-github-token'
            try:
                loaded = consumer.saved_result(fake_core, common.digest(fake_core.read_bytes()),
                                               self.root / 'history.json')
            finally:
                for name in ('GATEHOUSE_CHECK_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'):
                    os.environ.pop(name, None)
            self.assertEqual(loaded['historical_integrity'], 'verified')
            child = json.loads(dump.read_text())
            self.assertEqual(set(child), {'PATH', 'LANG'})
            self.assertEqual(child['LANG'], 'C.UTF-8')

    def test_consumer_executable_pin_is_enforced(self):
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.saved_result(common.CORE, '0' * 64, self.root / 'history.json')
        self.assertIn('Core executable digest differs', str(raised.exception))

    def test_strict_json_bounds_reject_hostile_config(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-json-') as work:
            work = Path(work)
            cases = {
                'duplicate.json': '{"repository":"a/b","repository":"c/d"}',
                'nonfinite.json': '{"repository":NaN}',
            }
            for name, text in cases.items():
                path = work / name
                path.write_text(text)
                with self.assertRaises(consumer.Rejected, msg=name):
                    consumer.load(path)
            oversized = work / 'oversized.json'
            oversized.write_bytes(b'{"x":"' + b'a' * (16 * 1024 * 1024 + 1) + b'"}')
            with self.assertRaises(consumer.Rejected) as raised:
                consumer.load(oversized)
            self.assertIn('too large', str(raised.exception))


class CliPreview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.root, cls.verified = common.shared('pass')

    def _config_path(self, work):
        path = Path(work) / 'consumer.json'
        path.write_text(json.dumps(common.config_for(self.verified)))
        return path

    def test_preview_never_constructs_github_client(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-preview-') as work:
            argv = ['github_check.py', '--config', str(self._config_path(work)),
                    '--core', str(common.CORE), '--index', str(self.root / 'history.json')]
            saved, saved_argv = consumer.GitHub, sys.argv
            consumer.GitHub = lambda *args: (_ for _ in ()).throw(AssertionError('API constructed'))
            captured = []
            try:
                sys.argv = argv
                with mock.patch('builtins.print', captured.append):
                    consumer.main()
            finally:
                consumer.GitHub, sys.argv = saved, saved_argv
            output = json.loads(captured[0])
            self.assertEqual(output['delivery'], 'not-sent')
            self.assertEqual(output['payload']['conclusion'], 'success')

    def test_preview_cli_with_real_core_and_index(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-preview-') as work:
            output = subprocess.run(
                [sys.executable, str(common.CONSUMER),
                 '--config', str(self._config_path(work)), '--core', str(common.CORE),
                 '--index', str(self.root / 'history.json')],
                capture_output=True, text=True, cwd=work)
            self.assertEqual(output.returncode, 0, output.stderr)
            payload = json.loads(output.stdout)
            self.assertEqual(payload['delivery'], 'not-sent')
            self.assertEqual(payload['payload']['conclusion'], 'success')

    def test_apply_without_token_fails_without_state_mutation(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-apply-') as work:
            state = Path(work) / 'state.db'
            output = subprocess.run(
                [sys.executable, str(common.CONSUMER),
                 '--config', str(self._config_path(work)), '--core', str(common.CORE),
                 '--index', str(self.root / 'history.json'), '--apply', '--state', str(state)],
                capture_output=True, text=True, cwd=work,
                env={key: value for key, value in os.environ.items()
                     if key not in ('GATEHOUSE_CHECK_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')})
            self.assertEqual(output.returncode, 1)
            self.assertEqual(json.loads(output.stdout)['error_type'], 'Rejected')
            self.assertFalse(state.exists(), 'token failure must not create protected state')

    def test_withdrawal_cli_never_reads_historical_evidence(self):
        with tempfile.TemporaryDirectory(prefix='gatehouse-withdraw-') as work:
            config = common.config_for(self.verified, current_use_review='withdrawn',
                                       withdrawal_reason='operator withdrew current use')
            path = Path(work) / 'consumer.json'
            path.write_text(json.dumps(config))
            output = subprocess.run(
                [sys.executable, str(common.CONSUMER),
                 '--config', str(path), '--withdraw'],
                capture_output=True, text=True, cwd=work)
            self.assertEqual(output.returncode, 0, output.stderr)
            payload = json.loads(output.stdout)
            self.assertEqual(payload['payload']['external_id'], 'gate-withdrawal:1')
            rejected = subprocess.run(
                [sys.executable, str(common.CONSUMER),
                 '--config', str(path), '--withdraw', '--core', str(common.CORE),
                 '--index', str(self.root / 'history.json')],
                capture_output=True, text=True, cwd=work)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(json.loads(rejected.stdout)['error_type'], 'Rejected')


if __name__ == '__main__':
    unittest.main()
