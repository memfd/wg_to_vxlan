"""Converge additive firewalld entries for the dedicated WireGuard device."""
import json
import subprocess
import sys


def run(args):
    return subprocess.run(["firewall-cmd", *args], capture_output=True, text=True, timeout=20)


def output(args):
    result = run(args)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "Unable to read firewalld configuration")
    return result.stdout.strip()


def binding(scope, interface):
    zones = output(scope + ["--get-zones"]).split()
    for zone in zones:
        if interface in output(scope + ["--zone=" + zone, "--list-interfaces"]).split():
            return zone
    return None


def scoped_rule(source, destination, port=None):
    match = 'protocol value="icmp"' if port is None else f'port port="{port}" protocol="udp"'
    return f'rule family="ipv4" source address="{source}/32" destination address="{destination}/32" {match} accept'


def reconcile(c, mode):
    if mode not in ("verify", "plan", "apply"):
        raise ValueError("Invalid firewall operation")
    public_zone = binding([], c["uplink"]) or output(["--get-default-zone"])
    changes = []
    for scope in (["--permanent"], []):
        explicit_public = binding(scope, c["uplink"])
        if explicit_public and explicit_public != public_zone:
            raise ValueError("Public interface zone differs between runtime and permanent configuration")
        wg_zone = binding(scope, c["wg"])
        if wg_zone not in (None, "drop"):
            raise ValueError("Dedicated WireGuard interface already has a different zone binding")
        if not wg_zone:
            changes.append(scope + ["--zone=drop", "--add-interface=" + c["wg"]])
        for zone, rule in (
            (public_zone, scoped_rule(c["remote_public"], c["public"], c["wg_port"])),
            ("drop", scoped_rule(c["remote_tunnel"], c["tunnel"], c["vxlan_port"])),
            ("drop", scoped_rule(c["remote_tunnel"], c["tunnel"])),
        ):
            args = scope + ["--zone=" + zone]
            query = run(args + ["--query-rich-rule=" + rule])
            if query.returncode == 1 and query.stdout.strip() == "no":
                changes.append(args + ["--add-rich-rule=" + rule])
            elif query.returncode or query.stdout.strip() != "yes":
                raise ValueError(query.stderr.strip() or "Unexpected firewalld rule query result")
    if changes and mode == "verify":
        raise ValueError("Expected firewalld interface binding or scoped rule is missing")
    if mode == "apply":
        for change in changes:
            output(change)
        if changes:
            reconcile(c, "verify")
    return {"changed": bool(changes), "public_zone": public_zone}


if __name__ == "__main__":
    try:
        print(json.dumps(reconcile(json.load(sys.stdin), sys.argv[1])))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
