#!/usr/bin/env python3
"""Create one host-local WireGuard identity and an immutable point-to-point profile."""
import argparse
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager

OWNER = "# Managed by wg_to_vxlan.ovirt_l2"
WG_DIR = Path("/etc/wireguard")
NM_DIR = Path("/etc/NetworkManager/conf.d")


class Conflict(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Conflict(message)


def command(*args, stdin=None):
    proc = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=30)
    require(proc.returncode == 0, "Failed to execute " + args[0] + " " + args[1])
    return proc.stdout.strip()


def ifname(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}", value),
            "Specify a Linux interface name of up to 15 letters, digits, underscores or hyphens.")
    return value


def ipv4(value):
    ip = ipaddress.IPv4Address(value)
    require(isinstance(value, str) and not (ip.is_loopback or ip.is_link_local or
            ip.is_unspecified or ip.is_multicast or ip.is_reserved), "Specify a usable unicast IPv4 address.")
    return str(ip)


def key(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9+/]{43}=", value), "Invalid WireGuard key.")
    decoded = base64.b64decode(value, validate=True)
    require(len(decoded) == 32 and any(decoded) and base64.b64encode(decoded).decode() == value,
            "Invalid WireGuard key.")
    return value


def validate(cfg, needs_peer_key=True):
    interface, uplink = ifname(cfg["interface"]), ifname(cfg["uplink"])
    require(interface != uplink, "Tunnel and public uplink must use distinct interfaces.")
    for field in ("local", "peer", "endpoint"):
        ipv4(cfg[field])
    require(len({cfg["local"], cfg["peer"], cfg["endpoint"]}) == 3,
            "Tunnel addresses and peer public endpoint must be distinct.")
    for field, minimum, maximum in (("port", 1, 65535), ("mtu", 576, 65535)):
        require(type(cfg[field]) is int and minimum <= cfg[field] <= maximum,
                "Invalid " + field + " value.")
    if needs_peer_key:
        key(cfg["peer_key"])


def read_file(path, private):
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & (0o077 if private else 0o022) and info.st_size < 16384,
            "Unsafe existing file at " + str(path))
    return path.read_text()


def directory(path, *, create=False):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "Unsafe configuration directory at " + str(path))


def atomic_write(path, content, mode):
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".fabric-")
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        Path(temp).unlink(missing_ok=True)


@contextmanager
def transaction(interface, readonly):
    if readonly:
        yield
        return
    path = Path("/run") / ("wg-to-vxlan-wg-" + interface + ".lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o077, "Unsafe transaction lock.")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield


def profile(cfg, private):
    return (
        f"{OWNER}\n[Interface]\nPrivateKey = {private}\n"
        f"Address = {cfg['local']}/32\nMTU = {cfg['mtu']}\nListenPort = {cfg['port']}\n"
        f"Table = off\nPostUp = ip -4 route add {cfg['peer']}/32 dev %i src {cfg['local']}\n"
        f"\n[Peer]\nPublicKey = {cfg['peer_key']}\nAllowedIPs = {cfg['peer']}/32\n"
        f"Endpoint = {cfg['endpoint']}:{cfg['port']}\nPersistentKeepalive = 25\n"
    )


def live_link(interface):
    links = json.loads(command("ip", "-j", "-d", "link", "show"))
    return next((item for item in links if item["ifname"] == interface), None)


def check_routes(cfg, active):
    path = json.loads(command("ip", "-j", "-4", "route", "get", cfg["endpoint"]))
    require(len(path) == 1 and path[0].get("dev") == cfg["uplink"] and path[0].get("type", "unicast") == "unicast",
            "The route to the public endpoint must use the selected public uplink.")
    interfaces = json.loads(command("ip", "-j", "-4", "address", "show"))
    for item in interfaces:
        for address in item.get("addr_info", []):
            local = address["local"]
            ours = active and item["ifname"] == cfg["interface"] and local == cfg["local"]
            require(ours or local not in (cfg["local"], cfg["peer"]), "An inner address is already in use.")
    routes = json.loads(command("ip", "-j", "-4", "route", "show", "table", "main"))
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        net = ipaddress.IPv4Network(destination, strict=False)
        if not any(ipaddress.IPv4Address(cfg[k]) in net for k in ("local", "peer")):
            continue
        ours = active and str(net) == cfg["peer"] + "/32" and route.get("dev") == cfg["interface"]
        require(ours, "An inner tunnel address overlaps an existing route on the host.")


def check_nm(interface):
    rows = command("nmcli", "-t", "-f", "UUID,TYPE", "connection", "show")
    for row in rows.splitlines():
        uuid, kind = row.split(":", 1)
        if kind != "wireguard":
            continue
        name = command("nmcli", "-g", "connection.interface-name", "connection", "show", "uuid", uuid)
        if not name:
            name = command("nmcli", "-g", "connection.id", "connection", "show", "uuid", uuid)
        require(name != interface, "NetworkManager already has a profile for this WireGuard device.")


def verify(cfg, public, link):
    name = cfg["interface"]
    require(link and link.get("linkinfo", {}).get("info_kind") == "wireguard"
            and "UP" in link.get("flags", []) and link["mtu"] == cfg["mtu"], "Unexpected WireGuard link state.")
    require(command("wg", "show", name, "public-key") == public, "Running interface uses another local key.")
    require(command("wg", "show", name, "listen-port") == str(cfg["port"]), "Unexpected WireGuard listen port.")
    expected = {
        "allowed-ips": cfg["peer"] + "/32",
        "endpoints": cfg["endpoint"] + ":" + str(cfg["port"]),
        "persistent-keepalive": "25",
    }
    for field, value in expected.items():
        require(command("wg", "show", name, field).split() == [cfg["peer_key"], value],
                "Running WireGuard configuration differs for " + field)
    addresses = json.loads(command("ip", "-j", "-4", "address", "show", "dev", name))
    got = [(a["local"], a["prefixlen"]) for entry in addresses for a in entry.get("addr_info", [])]
    require(got == [(cfg["local"], 32)], "Unexpected address on WireGuard.")
    route = json.loads(command("ip", "-j", "-4", "route", "get", cfg["peer"], "from", cfg["local"]))
    require(len(route) == 1 and route[0].get("dev") == name, "Inner IPv4 route does not use WireGuard.")


def reconcile(cfg, action):
    name = ifname(cfg["interface"])
    is_identity = action.startswith("identity")
    readonly = action.endswith("-plan") or action == "verify"
    validate(cfg, needs_peer_key=not is_identity)
    key_path = WG_DIR / ("wg-to-vxlan-" + name + ".key")
    config_path = WG_DIR / (name + ".conf")
    nm_path = NM_DIR / ("90-wg-to-vxlan-" + name + ".conf")
    with transaction(name, readonly):
        directory(WG_DIR)
        existing = read_file(config_path, private=True)
        if existing is not None:
            require(existing.startswith(OWNER + "\n"), "Refusing to adopt a foreign wg-quick profile.")
        private = read_file(key_path, private=True)
        if private is not None:
            private = key(private.strip())
        link = live_link(name)
        require(not link or existing is not None and private is not None, "Refusing to adopt an existing device.")
        require(existing is None or private is not None, "Restore the original key for the existing profile.")
        check_routes(cfg, bool(link))
        check_nm(name)
        unit = "wg-quick@" + name + ".service"
        state = command("systemctl", "show", "--value", "-p", "ActiveState", unit)
        require(state in ("active", "inactive", "failed") and bool(link) == (state == "active"),
                "An existing interface or unit is in an unexpected state.")
        if not link:
            require(not command("ss", "-H", "-lun", "sport", "=", ":" + str(cfg["port"])),
                    "WireGuard listen port is already in use.")
        if is_identity:
            generated = private is None
            if generated and not readonly:
                directory(WG_DIR, create=True)
                private = key(command("wg", "genkey"))
                atomic_write(key_path, private + "\n", 0o600)
            public = key(command("wg", "pubkey", stdin=private + "\n")) if private else ""
            return {"public_key": public, "changed": generated}
        require(private is not None, "Prepare local identities on both endpoints first.")
        public = key(command("wg", "pubkey", stdin=private + "\n"))
        require(public != cfg["peer_key"], "The remote peer must have a different key.")
        desired = profile(cfg, private)
        require(existing in (None, desired), "Existing profile differs. Inspect and remove it during maintenance before rebuilding.")
        if link:
            verify(cfg, public, link)
        directory(NM_DIR)
        nm = (f"{OWNER}\n[device-wg-to-vxlan-{name}]\nmatch-device=interface-name:{name}\nmanaged=0\n")
        previous_nm = read_file(nm_path, private=False)
        require(previous_nm in (None, nm), "A foreign NetworkManager fragment uses the requested pathname.")
        if action == "verify":
            require(link and previous_nm == nm and existing == desired, "Incomplete WireGuard setup.")
        changed = existing is None or previous_nm is None
        if not readonly:
            if previous_nm is None:
                atomic_write(nm_path, nm, 0o644)
            if existing is None:
                atomic_write(config_path, desired, 0o600)
            # Retry configuration reload even after a previous interrupted start.
            command("restorecon", "-F", str(key_path), str(config_path), str(nm_path))
            command("nmcli", "general", "reload", "conf")
        return {"changed": changed, "running": bool(link)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("identity", "identity-plan", "configure", "configure-plan", "verify"))
    action = parser.parse_args().action
    try:
        require(os.geteuid() == 0, "WireGuard host configuration requires root.")
        print(json.dumps(reconcile(json.load(sys.stdin), action)))
        return 0
    except Conflict as error:
        print(json.dumps({"error": str(error)}))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": "WireGuard inspection failed (" + type(error).__name__ + ")."}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
