#!/usr/bin/python3
"""Manage one VXLAN port on an existing Linux bridge."""
import argparse
import ctypes
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import sys
import time

OWNER = "wg_to_vxlan.ovirt_l2:overlay:"
SYS = Path("/sys/class/net")
V6 = Path("/proc/sys/net/ipv6/conf")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15,
                            env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def checked(config):
    require(config.get("owner") == "wg_to_vxlan.ovirt_l2", "Missing overlay configuration owner")
    for key in ("bridge", "wg", "vx", "uplink"):
        name = config[key]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", name),
                f"Invalid Linux interface name for {key}")
    require(len({config[k] for k in ("bridge", "wg", "vx", "uplink")}) == 4,
            "Public uplink, tenant bridge, WireGuard and VXLAN must be distinct")
    for key in ("local", "remote"):
        require(isinstance(config[key], str) and str(ipaddress.IPv4Address(config[key])) == config[key],
                f"Invalid IPv4 {key}")
    require(config["local"] != config["remote"], "Local and remote tunnel addresses must differ")
    for key, low, high in (("vni", 1, 16777215), ("port", 1, 65535),
                           ("mtu", 576, 9000), ("wg_mtu", 626, 9216)):
        value = config[key]
        require(type(value) is int and low <= value <= high, f"Invalid {key}")
    require(config["mtu"] + 50 <= config["wg_mtu"], "WireGuard MTU cannot carry the inner frame")
    return config


def port_mac(c):
    identity = (c["local"] + "/" + c["vx"]).encode("ascii")
    return "fe:" + ":".join(f"{n:02x}" for n in hashlib.sha256(identity).digest()[:5])


def links():
    return {row["ifname"]: row for row in json.loads(run("ip", "-j", "-d", "link", "show"))}


def kind(row):
    return row.get("linkinfo", {}).get("info_kind")


def info(row):
    return row.get("linkinfo", {}).get("info_data", {})


def stable_mac(bridge, devices, candidate, assign_type):
    if assign_type == "3":  # NET_ADDR_SET, explicitly fixed by an administrator.
        return True
    # On its first port Linux may replace an automatically assigned MAC even if
    # the joining port has a numerically higher address.
    address = bridge["address"].lower()
    return candidate > address and any(
        dev.get("master") == bridge["ifname"] and dev.get("address", "").lower() == address
        for dev in devices.values()
    )


def check_bridge(c, devices):
    bridge = devices.get(c["bridge"], {})
    require(kind(bridge) == "bridge" and "UP" in bridge.get("flags", []),
            "Provision and bring up the selected Linux bridge first")
    require(bridge["mtu"] == c["mtu"], "Bridge and fabric inner MTUs differ")
    require(not int(info(bridge).get("vlan_filtering", 0)),
            "Select an untagged bridge with VLAN filtering disabled")
    require(devices.get(c["uplink"], {}).get("master") != c["bridge"],
            "The public uplink cannot belong to the tenant bridge")
    assigned = (SYS / c["bridge"] / "addr_assign_type").read_text().strip()
    require(stable_mac(bridge, devices, port_mac(c), assigned),
            "Pin a stable bridge MAC in its managed profile before attaching this port")
    return bridge


def validate_live(c, devices):
    bridge = check_bridge(c, devices)
    wg = devices.get(c["wg"], {})
    require(kind(wg) == "wireguard" and "UP" in wg.get("flags", []) and wg["mtu"] == c["wg_mtu"],
            "Expected WireGuard interface or MTU is unavailable")
    route = json.loads(run("ip", "-j", "-4", "route", "get", c["remote"], "from", c["local"]))
    require(len(route) == 1 and route[0].get("dev") == c["wg"],
            "Remote tunnel endpoint is not routed through the selected WireGuard interface")
    return bridge


def owned(c, row, devices, fresh_index=None):
    require(kind(row) == "vxlan", "Interface name belongs to another kind of link")
    alias = row.get("ifalias", "")
    if fresh_index is None:
        require(alias == OWNER + c["vx"], "Refusing an unowned VXLAN")
    else:
        require(row["ifindex"] == fresh_index and alias in ("", OWNER + c["vx"]),
                "New VXLAN changed identity")
        if not alias:
            require(not row.get("master") and "UP" not in row["flags"], "New VXLAN already in use")
    require(row.get("master") in (None, c["bridge"]), "VXLAN is attached to a different bridge")
    require(row["address"].lower() == port_mac(c) and row["mtu"] == c["mtu"],
            "Owned port MAC or MTU differs")
    data = info(row)
    for field, wanted in (("id", c["vni"]), ("port", c["port"]), ("local", c["local"]),
                          ("remote", c["remote"]), ("learning", False)):
        require(data.get(field) == wanted, "VXLAN differs in " + field)
    require(data.get("link", row.get("link")) in (c["wg"], devices[c["wg"]]["ifindex"]),
            "VXLAN underlay is not the selected WireGuard interface")
    for flag in ("external", "proxy", "gbp", "gpe", "rsc", "l2miss", "l3miss"):
        require(flag not in data or data[flag] in (0, False), "Unexpected VXLAN option: " + flag)


def check_nm(name, wait):
    deadline = time.monotonic() + (5 if wait else 0)
    while True:
        state = run("nmcli", "-g", "GENERAL.STATE", "device", "show", name).split()
        if state and state[0] == "10":
            return
        if time.monotonic() >= deadline:
            raise ValueError("NetworkManager must mark the VXLAN port unmanaged")
        time.sleep(0.2)


def nmstate_interfaces():
    import libnmstate
    return {iface["name"]: iface for iface in libnmstate.show()["interfaces"]}


def check_nmstate(c, attached):
    deadline = time.monotonic() + 5
    while True:
        state = nmstate_interfaces()
        port = state.get(c["vx"], {})
        ports = state.get(c["bridge"], {}).get("bridge", {}).get("port", [])
        if port.get("state") == "ignore":
            if not attached or (port.get("controller") == c["bridge"] and
                                any(p.get("name") == c["vx"] for p in ports)):
                return
        if time.monotonic() >= deadline:
            raise ValueError("nmstate must report the VXLAN as ignored with its expected bridge membership")
        time.sleep(0.25)


def check_fdb(c):
    entries = json.loads(run("bridge", "-j", "fdb", "show", "dev", c["vx"]))
    remote = [entry for entry in entries if "dst" in entry]
    require(any(e["dst"] == c["remote"] and e.get("mac") == "00:00:00:00:00:00" for e in remote),
            "Missing point-to-point flood FDB entry")
    require(all(e["dst"] == c["remote"] for e in remote), "Unexpected remote FDB destination")


def require_no_layer3(c):
    rows = json.loads(run("ip", "-j", "address", "show", "dev", c["vx"]))
    require(len(rows) == 1 and not rows[0]["addr_info"], "VXLAN bridge port has IP addresses")


def status(c):
    devices = links()
    validate_live(c, devices)
    row = devices.get(c["vx"], {})
    owned(c, row, devices)
    require(row.get("master") == c["bridge"] and "UP" in row["flags"], "VXLAN port is not attached and up")
    check_nm(c["vx"], False)
    check_nmstate(c, attached=True)
    require_no_layer3(c)
    check_fdb(c)


def reconcile(c):
    devices = links()
    bridge = validate_live(c, devices)
    name = c["vx"]
    row = devices.get(name)
    created = None
    tagged = False
    attached_now = False
    changed = False
    try:
        if row is None:
            run("ip", "link", "add", "name", name, "address", port_mac(c), "mtu", str(c["mtu"]),
                "type", "vxlan", "id", str(c["vni"]), "dev", c["wg"], "local", c["local"],
                "remote", c["remote"], "dstport", str(c["port"]), "nolearning")
            row = links()[name]
            created = row["ifindex"]
            owned(c, row, devices, fresh_index=created)
            run("ip", "link", "set", "dev", name, "alias", OWNER + name)
            tagged = True
            row = links()[name]
            require(row["ifindex"] == created, "Port changed during creation")
            changed = True
        owned(c, row, devices)
        check_nm(name, True)
        check_nmstate(c, attached=False)
        # Suppress only automatic link-local IPv6 on this port. Refuse to
        # discard addresses if an administrator put a routed service here.
        ipv6 = V6 / name / "disable_ipv6"
        if ipv6.exists() and ipv6.read_text().strip() != "1":
            rows = json.loads(run("ip", "-j", "address", "show", "dev", name))
            require(all(a["family"] == "inet6" and a["scope"] == "link" for a in rows[0]["addr_info"]),
                    "Refusing to change an addressed VXLAN")
            ipv6.write_text("1\n")
            changed = True
        require_no_layer3(c)
        check_fdb(c)
        if row.get("master") is None:
            run("ip", "link", "set", "dev", name, "master", c["bridge"])
            attached_now = True
            changed = True
            after = links()[c["bridge"]]
            require(after["ifindex"] == bridge["ifindex"] and after["address"] == bridge["address"],
                    "Bridge identity changed during attachment")
        if "UP" not in row["flags"]:
            run("ip", "link", "set", "dev", name, "up")
            changed = True
        status(c)
        return changed
    except Exception:
        if created is not None or attached_now:
            live = links()
            current = live.get(name)
            if current and (created is None or current["ifindex"] == created):
                owned(c, current, live, fresh_index=created if not tagged else None)
                if created is not None:
                    run("ip", "link", "delete", "dev", name)
                elif current.get("master") == c["bridge"]:
                    run("ip", "link", "set", "dev", name, "nomaster")
        raise


def artifact_paths(vx):
    return {
        "helper": Path("/usr/local/libexec/wg-to-vxlan-overlay.py"),
        "config": Path("/etc/wg-to-vxlan/overlay") / (vx + ".json"),
        "service": Path("/etc/systemd/system") / ("wg-to-vxlan-overlay-" + vx + ".service"),
        "timer": Path("/etc/systemd/system") / ("wg-to-vxlan-overlay-" + vx + ".timer"),
        "networkmanager": Path("/etc/NetworkManager/conf.d") / ("90-wg-to-vxlan-" + vx + ".conf"),
    }


def ensure_parents(path, create):
    for directory in reversed(path.parents):
        if create and not os.path.lexists(directory):
            directory.mkdir(mode=0o755, exist_ok=True)
        if os.path.lexists(directory):
            attrs = directory.lstat()
            require(stat.S_ISDIR(attrs.st_mode) and attrs.st_uid == 0 and not attrs.st_mode & 0o022,
                    "Unsafe parent directory: " + str(directory))


def present_artifact(path, expected, mode):
    if not os.path.lexists(path):
        return False
    attrs = path.lstat()
    require(stat.S_ISREG(attrs.st_mode) and attrs.st_uid == 0 and attrs.st_nlink == 1
            and stat.S_IMODE(attrs.st_mode) == mode and attrs.st_size == len(expected)
            and path.read_bytes() == expected, "Conflicting existing overlay file: " + str(path))
    return True


def reject_overrides(paths):
    for unit in (paths["service"].name, paths["timer"].name):
        # systemd resolves transient, generated and vendor units using paths
        # outside /etc/systemd/system as well.
        result = subprocess.run(["systemctl", "show", unit, "-p", "LoadState", "-p", "FragmentPath",
                                 "-p", "DropInPaths"], text=True, capture_output=True, timeout=15)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        require(result.returncode == 0 or (result.returncode == 4 and values.get("LoadState") == "not-found"),
                "Cannot inspect systemd unit: " + unit)
        require(not values.get("DropInPaths") and values.get("FragmentPath", "") in
                ("", str(Path("/etc/systemd/system") / unit)), "Conflicting systemd unit or drop-in: " + unit)
        for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
                          "/usr/lib/systemd/system"):
            candidate = Path(directory) / unit
            if directory != "/etc/systemd/system":
                require(not os.path.lexists(candidate), "Conflicting systemd unit: " + str(candidate))
            override = Path(str(candidate) + ".d")
            require(not os.path.lexists(override), "Conflicting systemd unit override: " + str(override))
    for directory in ("/run/NetworkManager/conf.d", "/usr/lib/NetworkManager/conf.d"):
        candidate = Path(directory) / paths["networkmanager"].name
        require(not os.path.lexists(candidate), "Conflicting NetworkManager configuration: " + str(candidate))


def create_artifact(path, content, mode):
    ensure_parents(path, True)
    fd, temp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as file:
            os.fchmod(file.fileno(), mode)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        # Never replace a file that appeared after preflight, even on the
        # first install. The role's separate installers share the same lock.
        # Linux renameat2(RENAME_NOREPLACE) leaves a single destination link
        # even if the process dies immediately after the atomic rename.
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.renameat2(-100, os.fsencode(temp), -100, os.fsencode(path), 1)
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(path))
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def artifacts(payload, install):
    c = checked(payload["config"])
    paths = artifact_paths(c["vx"])
    expected = {k: payload[k].encode("utf-8") for k in paths if k != "config"}
    expected["config"] = (json.dumps(c, sort_keys=True, indent=2) + "\n").encode()
    missing = {}
    reject_overrides(paths)
    for key, path in paths.items():
        ensure_parents(path, False)
        mode = 0o755 if key == "helper" else 0o644
        if not present_artifact(path, expected[key], mode):
            missing[key] = mode
    if install:
        for key, mode in missing.items():
            create_artifact(paths[key], expected[key], mode)
        run("restorecon", "-F", *(str(path) for path in paths.values()))
    return bool(missing) if install else False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["validate", "plan", "sync", "verify", "check-assets", "install-assets"])
    parser.add_argument("config", help="JSON file or - for standard input")
    args = parser.parse_args()
    payload = json.load(sys.stdin) if args.config == "-" else json.loads(Path(args.config).read_text())
    if args.action == "check-assets":
        return artifacts(payload, False)
    if args.action == "install-assets":
        fd = os.open("/run/wg-to-vxlan-overlay-install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return artifacts(payload, True)
        finally:
            os.close(fd)
    c = checked(payload)
    if args.action == "validate":
        return False
    if args.action == "plan":
        nmstate_interfaces()  # Check the oVirt network manager bindings before provisioning.
        devices = links()
        check_bridge(c, devices)
        if c["vx"] in devices:
            owned(c, devices[c["vx"]], devices)
        return False
    if args.action == "verify":
        status(c)
        return False
    # Serialize commands from the boot timer and the Ansible run on this host.
    lock = os.open("/run/wg-to-vxlan-overlay-" + c["vx"] + ".lock",
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return reconcile(c)
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        print(json.dumps({"changed": main()}))
    except (ValueError, OSError, ImportError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
