import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'roles/wireguard/files/transport.py'
spec = importlib.util.spec_from_file_location('transport', SOURCE)
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


def config():
    return dict(interface='wgpair0', uplink='uplink0', local='10.50.0.1', peer='10.50.0.2',
                endpoint='192.0.2.20', port=51820, mtu=1440, peer_key=base64.b64encode(b'b'*32).decode())


class WireGuardTests(unittest.TestCase):
    def test_profile_has_only_one_inner_host_route(self):
        cfg = config()
        result = transport.profile(cfg, 'synthetic')
        self.assertIn('Table = off\n', result)
        self.assertIn('PostUp = ip -4 route add 10.50.0.2/32 dev %i src 10.50.0.1\n', result)
        self.assertIn('AllowedIPs = 10.50.0.2/32\n', result)
        self.assertNotIn('0.0.0.0/0', result)

    def test_validation_rejects_unsafe_names_and_address_aliases(self):
        for update in [dict(interface='--help'), dict(local='0.0.0.0'), dict(local='10.50.0.2'),
                       dict(endpoint='10.50.0.1'), dict(interface='uplink0'), dict(port=True)]:
            with self.subTest(update=update), self.assertRaises(ValueError):
                transport.validate(dict(config(), **update))

    def test_host_with_broad_route_overlapping_private_tunnel_is_refused(self):
        replies = ['[{"dev":"uplink0"}]', '[]', '[{"dst":"10.50.0.0/16","dev":"private0"}]']
        with patch.object(transport,'command',side_effect=replies), self.assertRaisesRegex(transport.Conflict,'overlaps'):
            transport.check_routes(config(),False)

    def test_existing_identical_peer_route_and_own_address_allowed(self):
        replies = ['[{"dev":"uplink0"}]',
                   '[{"ifname":"wgpair0","addr_info":[{"local":"10.50.0.1","prefixlen":32}]}]',
                   '[{"dst":"10.50.0.2","dev":"wgpair0"},{"dst":"default","dev":"uplink0"}]']
        with patch.object(transport,'command',side_effect=replies):
            transport.check_routes(config(),True)

    def test_foreign_device_or_missing_owned_key_blocks_identity_generation(self):
        for profile, link in [(None, {'ifname':'wgpair0'}),(transport.OWNER+'\n', None)]:
            with self.subTest(profile=profile), patch.object(transport,'read_file',side_effect=[profile,None]), \
                    patch.object(transport,'live_link',return_value=link), patch.object(transport,'directory'), \
                    patch.object(transport,'command') as runner, self.assertRaises(transport.Conflict):
                transport.reconcile(config(),'identity-plan')
            runner.assert_not_called()

    def test_live_wireguard_netlink_and_machine_readable_wg_outputs(self):
        cfg = config()
        local_public_key = base64.b64encode(b'a' * 32).decode()
        link = dict(ifindex=9, ifname=cfg['interface'], flags=['POINTOPOINT', 'NOARP', 'UP', 'LOWER_UP'],
                    mtu=cfg['mtu'], qdisc='noqueue', operstate='UNKNOWN', link_type='none',
                    linkinfo={'info_kind': 'wireguard'})
        allowed = cfg['peer_key'] + '\t' + cfg['peer'] + '/32'
        expected = [local_public_key, str(cfg['port']), allowed,
                    cfg['peer_key'] + '\t' + cfg['endpoint'] + ':' + str(cfg['port']),
                    cfg['peer_key'] + '\t25',
                    json.dumps([dict(ifname=cfg['interface'], addr_info=[dict(
                        family='inet', local=cfg['local'], prefixlen=32, scope='global')])]),
                    json.dumps([dict(dst=cfg['peer'], dev=cfg['interface'], **{'from': cfg['local']})])]
        with patch.object(transport, 'command', side_effect=expected):
            transport.verify(cfg, local_public_key, link)
        extra_peer = expected.copy()
        extra_peer[2] += '\n' + local_public_key + '\t192.0.2.200/32'
        with patch.object(transport, 'command', side_effect=extra_peer), self.assertRaisesRegex(transport.Conflict, 'allowed-ips'):
            transport.verify(cfg, local_public_key, link)

    def test_nm_terse_listing_rejects_an_inactive_profile_bound_by_name(self):
        outputs = ['synthetic-ethernet:802-3-ethernet\nsynthetic-wg:wireguard', '', 'wgpair0']
        with patch.object(transport, 'command', side_effect=outputs), self.assertRaisesRegex(transport.Conflict, 'NetworkManager'):
            transport.check_nm('wgpair0')

    def test_read_only_identity_does_not_generate_key(self):
        def inspect(*args):
            return 'inactive' if args[0]=='systemctl' else ''
        with patch.object(transport,'read_file',return_value=None), patch.object(transport,'directory'), \
                patch.object(transport,'live_link',return_value=None), patch.object(transport,'check_routes'), \
                patch.object(transport,'check_nm'), patch.object(transport,'command',side_effect=inspect) as runner, \
                patch.object(transport,'atomic_write') as write:
            self.assertEqual(transport.reconcile(config(),'identity-plan'), {'changed':True,'public_key':''})
            self.assertTrue(all(c.args[0] != 'wg' for c in runner.call_args_list))
            write.assert_not_called()

    def test_rejects_unsupported_or_private_output_on_subprocess_failure(self):
        with patch.object(transport.subprocess,'run',return_value=transport.subprocess.CompletedProcess(
                ['wg','pubkey'],1,'private stdout','private stderr')), self.assertRaises(transport.Conflict) as err:
            transport.command('wg','pubkey',stdin='private')
        self.assertNotIn('private',str(err.exception))

    def test_rejects_foreign_configuration_while_link_is_down(self):
        with patch.object(transport,'directory'), patch.object(transport,'read_file',return_value='[Interface]\n'), \
                self.assertRaisesRegex(transport.Conflict,'foreign'):
            transport.reconcile(config(),'configure-plan')


if __name__ == '__main__':
    unittest.main()
