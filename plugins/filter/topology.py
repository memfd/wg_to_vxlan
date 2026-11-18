"""Validate a complete two-host inventory before touching either endpoint."""
import ipaddress
import re

from ansible.errors import AnsibleFilterError


def ipv4(raw):
    if not isinstance(raw, str):
        raise AnsibleFilterError("Use a dotted-decimal IPv4 address without a prefix")
    try:
        address = ipaddress.IPv4Address(raw)
    except ValueError as error:
        raise AnsibleFilterError(str(error)) from error
    if address.is_multicast or address.is_loopback or address.is_unspecified or address.is_reserved or address.is_link_local:
        raise AnsibleFilterError("A routable unicast IPv4 address is required")
    return str(address)


def peer_settings(hosts, hostvars, local):
    if len(hosts) != 2 or local not in hosts:
        raise AnsibleFilterError("The ovirt_fabric group must contain exactly two hosts")
    peer = next(host for host in hosts if host != local)
    addresses = [ipv4(hostvars[h][name]) for h in hosts
                 for name in ("fabric_public_ipv4", "fabric_wg_address")]
    if len(set(addresses)) != 4:
        raise AnsibleFilterError("Use four distinct endpoint and tunnel addresses")
    return {"host": peer, "public": ipv4(hostvars[peer]["fabric_public_ipv4"]),
            "tunnel": ipv4(hostvars[peer]["fabric_wg_address"])}


def validate_config(c):
    interfaces = [c[k] for k in ("uplink", "bridge", "wg", "vxlan")]
    if any(not isinstance(n, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,14}", n) for n in interfaces):
        raise AnsibleFilterError("Supply distinct Linux interface names of 1 to 15 characters")
    if len(set(interfaces)) != len(interfaces):
        raise AnsibleFilterError("Bridge, uplink, WireGuard and VXLAN must be distinct")
    for key, upper in (("wg_port", 65535), ("vxlan_port", 65535), ("vni", 16777215)):
        if not isinstance(c[key], int) or isinstance(c[key], bool) or not 1 <= c[key] <= upper:
            raise AnsibleFilterError("Invalid integer for " + key)
    if c["wg_port"] == c["vxlan_port"]:
        raise AnsibleFilterError("Choose separate UDP ports for WireGuard and VXLAN")
    if not all(isinstance(c[k], int) and not isinstance(c[k], bool) for k in ("wg_mtu", "inner_mtu")) or not (1280 <= c["inner_mtu"] <= 9000 and c["inner_mtu"] + 50 <= c["wg_mtu"] <= 9216):
        raise AnsibleFilterError("WireGuard MTU must accommodate the inner MTU plus 50 bytes")
    if c["probe"]:
        ipv4(c["probe"])
    return True


class FilterModule:
    def filters(self):
        return {"peer_settings": peer_settings, "valid_config": validate_config}
