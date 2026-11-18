import copy
import os
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "roles/overlay/files/overlay.py"
SPEC = importlib.util.spec_from_file_location("fabric_overlay", SOURCE)
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


def config():
    return dict(owner="wg_to_vxlan.ovirt_l2", bridge="brvm", vx="vxfabric0", wg="wgfabric0", uplink="wan0",
                local="10.240.0.1", remote="10.240.0.2",
                mtu=1390, wg_mtu=1440, vni=1000, port=4789)


def topology(c):
    return {
        c["bridge"]: {"ifname": c["bridge"], "ifindex": 2, "address": "02:00:00:00:00:01",
                      "flags": ["UP"], "mtu": 1390, "linkinfo": {"info_kind": "bridge"}},
        c["wg"]: {"ifname": c["wg"], "ifindex": 3, "mtu": 1440, "flags": ["UP"],
                  "linkinfo": {"info_kind": "wireguard"}},
        c["vx"]: {"ifname": c["vx"], "ifindex": 4, "address": overlay.port_mac(c),
                  "mtu": 1390, "master": c["bridge"], "flags": ["UP"],
                  "ifalias": overlay.OWNER + c["vx"], "linkinfo": {
                      "info_kind": "vxlan", "info_data": {
                          "id": c["vni"], "port": c["port"], "remote": c["remote"],
                          "local": c["local"], "learning": False, "link": c["wg"]
                      }
                  }}
    }


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.c = config()
        self.devices = topology(self.c)

    def test_mtu_and_interface_collision_checked(self):
        overlay.checked(self.c)
        for changes in ({"mtu": 1500}, {"wg": "brvm"}, {"bridge": "../x"}, {"vx": "x;reboot"},
                        {"uplink": "brvm"}, {"remote": self.c["local"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                overlay.checked({**self.c, **changes})

    def test_bridge_mac_must_be_stable_before_adding_first_port(self):
        bridge = self.devices["brvm"]
        self.assertFalse(overlay.stable_mac(bridge, {}, overlay.port_mac(self.c), "1"))
        self.assertTrue(overlay.stable_mac(bridge, {}, overlay.port_mac(self.c), "3"))
        anchor = dict(master="brvm", address=bridge["address"])
        self.assertTrue(overlay.stable_mac(bridge, {"nic": anchor}, overlay.port_mac(self.c), "1"))
        self.assertFalse(overlay.stable_mac(bridge, {"nic": anchor}, "00:00:00:00:00:01", "1"))

    def test_must_not_expose_public_uplink_or_vlan_filtering(self):
        for change in ("public", "vlan"):
            devices = copy.deepcopy(self.devices)
            if change == "public":
                devices["wan0"] = {"master": "brvm"}
            else:
                devices["brvm"]["linkinfo"]["info_data"] = {"vlan_filtering": 1}
            with self.subTest(change=change), self.assertRaises(ValueError):
                overlay.check_bridge(self.c, devices)

    def test_refuses_foreign_immutable_name_underlay_and_master(self):
        for key, value in (("ifalias", "other"), ("master", "other"), ("mtu", 1200),
                           ("address", "02:00:00:00:00:02")):
            row = {**self.devices[self.c["vx"]], key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                overlay.owned(self.c, row, self.devices)
        row = copy.deepcopy(self.devices[self.c["vx"]])
        row["linkinfo"]["info_data"]["link"] = "wan0"
        with self.assertRaisesRegex(ValueError, "underlay"):
            overlay.owned(self.c, row, self.devices)

    def test_el9_underlay_name_and_numeric_ifindex(self):
        row = self.devices[self.c["vx"]]
        overlay.owned(self.c, row, self.devices)
        row["linkinfo"]["info_data"]["link"] = 3
        overlay.owned(self.c, row, self.devices)

    def test_healthy_port_only_queries_state(self):
        with patch.object(overlay, "links", return_value=self.devices), \
                patch.object(overlay, "validate_live", return_value=self.devices["brvm"]), \
                patch.object(overlay, "check_nm"), patch.object(overlay, "check_nmstate"), patch.object(overlay, "require_no_layer3"), \
                patch.object(overlay, "check_fdb"), patch.object(overlay, "run") as command:
            self.assertFalse(overlay.reconcile(self.c))
            command.assert_not_called()

    def test_repair_bridge_membership_without_recreating_tunnel(self):
        row = self.devices[self.c["vx"]]
        del row["master"]
        command = ("ip", "link", "set", "dev", self.c["vx"], "master", "brvm")

        def attach(*args):
            self.assertEqual(args, command)
            row["master"] = "brvm"

        with patch.object(overlay, "links", return_value=self.devices), \
                patch.object(overlay, "validate_live", return_value=self.devices["brvm"]), \
                patch.object(overlay, "check_nm"), patch.object(overlay, "check_nmstate"), patch.object(overlay, "require_no_layer3"), \
                patch.object(overlay, "check_fdb"), patch.object(overlay, "run", side_effect=attach) as run:
            self.assertTrue(overlay.reconcile(self.c))
            run.assert_called_once_with(*command)

    def test_failure_after_create_only_deletes_just_created_owned_port(self):
        template = self.devices.pop(self.c["vx"])
        name = self.c["vx"]
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:3] == ("ip", "link", "add"):
                self.devices[name] = {**template, "flags": [], "ifalias": "", "master": None}
            elif "alias" in args:
                self.devices[name]["ifalias"] = args[-1]
            elif args[:3] == ("ip", "link", "delete"):
                del self.devices[name]
            else:
                self.fail(str(args))

        with patch.object(overlay, "links", return_value=self.devices), \
                patch.object(overlay, "validate_live", return_value=self.devices["brvm"]), \
                patch.object(overlay, "check_nm", side_effect=ValueError("managed")), \
                patch.object(overlay, "run", side_effect=fake_run), self.assertRaisesRegex(ValueError, "managed"):
            overlay.reconcile(self.c)
        self.assertNotIn(name, self.devices)
        self.assertEqual(calls[-1], ("ip", "link", "delete", "dev", name))

    def test_presence_only_gbp_flag_is_rejected(self):
        row = self.devices[self.c["vx"]]
        row["linkinfo"]["info_data"]["gbp"] = None
        with self.assertRaisesRegex(ValueError, "gbp"):
            overlay.owned(self.c, row, self.devices)

    def test_nmstate_requires_ignored_port_with_bridge_membership(self):
        view = {self.c["vx"]: {"state": "ignore", "controller": "brvm"},
                "brvm": {"bridge": {"port": [{"name": self.c["vx"]}]}}}
        with patch.object(overlay, "nmstate_interfaces", return_value=view):
            overlay.check_nmstate(self.c, attached=True)
        view[self.c["vx"]]["controller"] = "different"
        with patch.object(overlay, "nmstate_interfaces", return_value=view), \
                patch.object(overlay.time, "monotonic", side_effect=[0, 6]), \
                self.assertRaisesRegex(ValueError, "membership"):
            overlay.check_nmstate(self.c, attached=True)

    def test_symlink_or_nonmatching_asset_blocks_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unit"
            target.symlink_to(Path(tmp) / "missing")
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                overlay.present_artifact(target, b"example", 0o644)
            target.unlink()
            target.write_bytes(b"foreign")
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                overlay.present_artifact(target, b"example", 0o644)

    def test_atomic_creation_preserves_file_appearing_after_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unit"
            with patch.object(overlay, "ensure_parents"):
                overlay.create_artifact(target, b"first", 0o644)
                with self.assertRaises(FileExistsError):
                    overlay.create_artifact(target, b"second", 0o644)
            self.assertEqual(target.read_bytes(), b"first")
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(os.listdir(tmp), ["unit"])

    def test_fdb_requires_only_the_configured_peer(self):
        rows = ('[{"mac":"00:00:00:00:00:00","dst":"10.240.0.2"},'
                '{"mac":"fe:01:02:03:04:05","dst":"10.240.0.8"}]')
        with patch.object(overlay, "run", return_value=rows), self.assertRaisesRegex(ValueError, "Unexpected"):
            overlay.check_fdb(self.c)


if __name__ == "__main__":
    unittest.main()
