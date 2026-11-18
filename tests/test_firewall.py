import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

module_path = Path(__file__).resolve().parents[1] / 'roles/firewall/files/scoped_rules.py'
spec = importlib.util.spec_from_file_location('scoped_rules', module_path)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


class FirewallTest(unittest.TestCase):
    def setUp(self):
        self.data = dict(uplink='ethA', wg='wgA', public='192.0.2.10', remote_public='198.51.100.20',
                         tunnel='10.200.0.1', remote_tunnel='10.200.0.2', wg_port=51820, vxlan_port=4789)
        self.entries = set()
        self.bindings = {(scope, 'public', 'ethA') for scope in (True, False)}
        self.changes = 0

    def firewalld(self, args):
        perm = '--permanent' in args
        opts = [a for a in args if a != '--permanent']
        zone = next((a[7:] for a in opts if a.startswith('--zone=')), '')
        cmd = opts[-1]
        rc, out = 0, ''
        if cmd == '--get-zones':
            out = 'drop public trusted'
        elif cmd == '--list-interfaces':
            out = ' '.join(dev for permanent, z, dev in self.bindings if (permanent, z) == (perm, zone))
        elif cmd.startswith('--add-interface='):
            self.changes += 1
            self.bindings.add((perm, zone, cmd.split('=', 1)[1]))
        elif cmd.startswith('--query-rich-rule='):
            found = (perm, zone, cmd.split('=', 1)[1]) in self.entries
            rc, out = (0, 'yes') if found else (1, 'no')
        elif cmd.startswith('--add-rich-rule='):
            self.changes += 1
            self.entries.add((perm, zone, cmd.split('=', 1)[1]))
        else:
            self.fail(args)
        return subprocess.CompletedProcess(args, rc, out, '')

    def test_plan_apply_retry_and_verify(self):
        with patch.object(fw, 'run', self.firewalld):
            self.assertTrue(fw.reconcile(self.data, 'plan')['changed'])
            self.assertEqual(self.changes, 0)
            self.assertTrue(fw.reconcile(self.data, 'apply')['changed'])
            self.assertEqual(self.changes, 8)
            self.assertFalse(fw.reconcile(self.data, 'verify')['changed'])
            self.assertFalse(fw.reconcile(self.data, 'apply')['changed'])
            public = [r for p,z,r in self.entries if z == 'public']
            self.assertTrue(all('51820' in r and '198.51.100.20/32' in r and '192.0.2.10/32' in r for r in public))

    def test_foreign_zone_refuses_before_any_writes(self):
        self.bindings.add((False, 'trusted', 'wgA'))
        with patch.object(fw, 'run', self.firewalld), self.assertRaisesRegex(ValueError, 'different zone'):
            fw.reconcile(self.data, 'apply')
        self.assertEqual(self.changes, 0)
