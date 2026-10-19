"""Paired full-quality identity acceptance for the result boundary (#139).

Every report comes from the shipped CLI over the real signed collector fixture
reused from common.py. Both paired runs share one fixture root and the same
collector executable bytes because the absolute executable path enters the
collector-runtime settings digest; only trusted config bytes are re-pinned and
the request is re-signed with a fresh nonce between variants.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

consumer = common.consumer()


class PairedFullQualityIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not common.CORE.is_file():
            raise unittest.SkipTest(f'built Core binary is required: {common.CORE}')
        cls.work = Path(tempfile.mkdtemp(prefix='gatehouse-identity-'))
        (cls.work / 'root').mkdir(mode=0o700)
        cls.root, cls.baseline = common.build(cls.work / 'root')
        cls.collector_digest = common.digest((cls.root / 'collector.py').read_bytes())
        cls.policy_bytes = (cls.root / '.harness-gate/policy.json').read_bytes()
        cls.flow_bytes = (cls.root / '.harness-gate/flow.toml').read_bytes()

        def tighten_threshold(root):
            policy = json.loads((root / '.harness-gate/policy.json').read_text())
            rule = policy['rules'][0]
            rule['limit']['covered'] = 5
            rule['operator'] = 'gt'
            (root / '.harness-gate/policy.json').write_text(json.dumps(policy, indent=2))

        cls.threshold, _ = common.variant(cls.root, 'threshold-variant',
                                          mutate=tighten_threshold, expect_failure=True)

        def widen_execution(root):
            (root / '.harness-gate/policy.json').write_bytes(cls.policy_bytes)
            (root / '.harness-gate/flow.toml').write_bytes(
                cls.flow_bytes + b'\n[execution]\nmax_parallel = 2\n')

        cls.execution, _ = common.variant(cls.root, 'execution-variant',
                                          mutate=widen_execution)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def identities(self, verified):
        return verified['result']['identities']

    def test_baseline_complete_full_quality_result(self):
        result = self.baseline['result']
        self.assertEqual(self.baseline['historical_integrity'], 'verified')
        self.assertEqual(result['status'], 'PASS')
        self.assertIs(result['passed'], True)
        self.assertIs(result['evidence_complete'], True)
        self.assertEqual(result['quality']['phase'], 'complete')
        self.assertEqual(result['quality']['full_quality_status'], 'pass')
        identities = self.identities(self.baseline)
        self.assertIs(identities['policy_binding_complete'], True)
        for key in ('verification_policy_identity', 'quality_policy_identity',
                    'runtime_bundle_digest'):
            self.assertIsInstance(identities[key], str)
            self.assertTrue(identities[key])

    def test_threshold_edit_changes_policy_not_runtime(self):
        base, changed = self.identities(self.baseline), self.identities(self.threshold)
        self.assertEqual(self.threshold['historical_integrity'], 'verified')
        self.assertNotEqual(changed['quality_policy_identity'],
                            base['quality_policy_identity'])
        self.assertNotEqual(changed['verification_policy_identity'],
                            base['verification_policy_identity'])
        self.assertEqual(changed['runtime_bundle_digest'], base['runtime_bundle_digest'])
        result = self.threshold['result']
        self.assertEqual(result['status'], 'FAIL')
        self.assertIs(result['passed'], False)
        self.assertIs(result['evidence_complete'], True)
        self.assertEqual(result['quality']['full_quality_status'], 'fail')

    def test_execution_edit_changes_runtime_not_policy(self):
        base, changed = self.identities(self.baseline), self.identities(self.execution)
        self.assertEqual(self.execution['historical_integrity'], 'verified')
        self.assertEqual(changed['quality_policy_identity'],
                         base['quality_policy_identity'])
        self.assertEqual(changed['verification_policy_identity'],
                         base['verification_policy_identity'])
        self.assertNotEqual(changed['runtime_bundle_digest'], base['runtime_bundle_digest'])
        result = self.execution['result']
        self.assertEqual(result['status'], 'PASS')
        self.assertIs(result['passed'], True)
        self.assertEqual(result['quality']['phase'], 'complete')
        self.assertEqual(result['quality']['full_quality_status'], 'pass')
        self.assertEqual(common.digest((self.root / 'collector.py').read_bytes()),
                         self.collector_digest)

    def test_old_result_rejected_under_new_runtime_requirement(self):
        old, new = self.identities(self.baseline), self.identities(self.execution)
        # Policy equality is not reuse permission: only the runtime differs.
        self.assertEqual(new['quality_policy_identity'], old['quality_policy_identity'])
        self.assertNotEqual(new['runtime_bundle_digest'], old['runtime_bundle_digest'])
        config = common.config_for(self.baseline)
        config['runtime_bundle_digest'] = new['runtime_bundle_digest']
        with self.assertRaises(consumer.Rejected) as raised:
            consumer.mapping(config, self.baseline)
        self.assertIn('runtime_bundle_digest', str(raised.exception))
        self.assertEqual(self.identities(self.baseline)['current_applicability'],
                         'not_proven')
        # The trusted consumer rejects before constructing any API transport.
        with tempfile.TemporaryDirectory(prefix='gatehouse-consumer-') as work:
            path = Path(work) / 'consumer.json'
            path.write_text(json.dumps(config))
            argv = ['github_check.py', '--config', str(path), '--core', str(common.CORE),
                    '--index', str(self.root / 'history.json'), '--apply',
                    '--state', str(Path(work) / 'state.db')]
            saved_argv = sys.argv
            try:
                sys.argv = argv
                with mock.patch.object(consumer, 'GitHub',
                                       side_effect=AssertionError('API constructed')):
                    with self.assertRaises(consumer.Rejected):
                        consumer.main()
            finally:
                sys.argv = saved_argv
            self.assertFalse((Path(work) / 'state.db').exists(),
                             'rejection must not create protected state')
        # The old report stays historically verifiable while applicability is
        # not proven for the new runtime requirement.
        with tempfile.TemporaryDirectory(prefix='gatehouse-old-') as work:
            config2 = common.config_for(self.baseline)
            path = Path(work) / 'consumer.json'
            path.write_text(json.dumps(config2))
            output = subprocess.run(
                [sys.executable, str(common.CONSUMER),
                 '--config', str(path), '--core', str(common.CORE),
                 '--index', str(self.root / 'history.json')],
                capture_output=True, text=True, cwd=work,
                env={key: value for key, value in os.environ.items()
                     if key not in ('GATEHOUSE_CHECK_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')})
            self.assertEqual(output.returncode, 0, output.stderr)
            payload = json.loads(output.stdout)
            self.assertEqual(payload['delivery'], 'not-sent')
            self.assertEqual(payload['payload']['conclusion'], 'success')
            self.assertEqual(self.baseline['historical_integrity'], 'verified')
            self.assertEqual(self.baseline['current_applicability'], 'not_evaluated')


if __name__ == '__main__':
    unittest.main()
