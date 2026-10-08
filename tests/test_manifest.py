import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class VaultManifestTest(unittest.TestCase):
    def test_manifest_declares_pack_unpack_order(self):
        doc = json.loads((ROOT / 'manifest.json').read_text())
        self.assertEqual(doc['schema'], 'homeserver.vault.payload.manifest.v1')
        self.assertEqual(doc['install_target'], '/vault/scripts')
        self.assertIn('chrysalis packs', doc['install_method'])
        self.assertEqual(doc['deploy_order']['after'], ['keyman-first-module', 'sudoers-policy-placement'])
        self.assertIn('sbin-path-placement', doc['deploy_order']['before'])
        self.assertEqual(set(doc['consumers']), {'deployables', 'harmonia', 'caduceus'})

    def test_manifest_records_encryption_boundary(self):
        doc = json.loads((ROOT / 'manifest.json').read_text())
        enc = doc['encryption_boundary']
        self.assertEqual(enc['vault_partition_label'], 'homeserver-vault')
        self.assertIn('luksFormat', enc['legacy_bootstrap_meaning'])
        self.assertIn('/root/key/skeleton.key', enc['legacy_bootstrap_meaning'])
        self.assertIn('ephemeral key', enc['finale_cleanup_meaning'])
        self.assertIs(enc['secret_values_allowed'], False)

    def test_payload_files_exist_and_no_secret_literals(self):
        doc = json.loads((ROOT / 'manifest.json').read_text())
        self.assertIn('init.sh', doc['payload_files'])
        forbidden = ['ROOT_PASSWORD=', 'FORGEJO_TOKEN=', 'DEPLOY_KEY=', 'BEGIN OPENSSH PRIVATE KEY']
        for rel in doc['payload_files']:
            path = ROOT / rel
            self.assertTrue(path.exists(), rel)
            if path.suffix in {'.png', '.jpg', '.jpeg', '.gif', '.crt'}:
                continue
            try:
                text = path.read_text()
            except UnicodeDecodeError:
                continue
            for needle in forbidden:
                self.assertNotIn(needle, text, rel)

if __name__ == '__main__':
    unittest.main()
