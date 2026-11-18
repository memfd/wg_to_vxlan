# L2 connectivity for oVirt over public IPv4

[Русская версия](README-ru.md)

`wg_to_vxlan.ovirt_l2` connects an existing Linux bridge on each of two oVirt hosts. A guest on either bridge can exchange Ethernet frames with guests on the other. The hosts need routed IPv4 connectivity between their public endpoints. WireGuard encrypts that traffic, and a point-to-point VXLAN carries guest Ethernet frames, including ARP and DHCP broadcasts.

```text
+-------------------------+                      +-------------------------+
|       oVirt host A      |                      |       oVirt host B      |
|       [ Guest A ]       |                      |       [ Guest B ]       |
|            |            |                      |            |            |
|     [ Linux bridge ]    |                      |     [ Linux bridge ]    |
|            |            |                      |            |            |
|      [ VXLAN port ]     |                      |      [ VXLAN port ]     |
|            |            |  Public IPv4 / UDP   |            |            |
|      [ WireGuard ]------+<-------------------->+------[ WireGuard ]      |
+-------------------------+                      +-------------------------+
```

Choose one logical VM network to extend. Use the Engine or your normal VDSM network workflow to prepare its Linux bridge on each host. For a fresh server with a single public NIC, prepare the standalone bridge as described in the [operations guide](docs/operations.md). The bridge names may differ. Select an active untagged bridge with VLAN filtering disabled. For an empty bridge configure a persistent MAC address first. Both ends must represent the same Ethernet segment, with compatible guest addressing, DHCP and MTU. This collection handles the tunnel and bridge attachment. Host enrollment, storage and guest IP configuration remain administrator tasks.

## Requirements

- A controller with ansible-core 2.19 or later, SSH access and privilege escalation on both hosts.
- Two Enterprise Linux 9 hosts with systemd, active NetworkManager and firewalld, Python bindings for libnmstate, Linux bridge networking and kernel support for WireGuard and VXLAN. The configured repositories must supply WireGuard tools and the required system packages.
- A fixed public IPv4 address assigned to each host, a working route to the other endpoint, and a UDP port reachable from that peer. Include provider firewalls in this check.
- The chosen bridge on each host, an unused tunnel interface name on each side, two unused WireGuard tunnel addresses and a VNI for the pair.
- One forwarding path between the selected bridges. A second L2 path can loop broadcast and unknown-unicast frames.

## Install and connect

Build the collection from this directory and install it on the controller.

```bash
mkdir -p dist
ansible-galaxy collection build --output-path dist
ansible-galaxy collection install dist/wg_to_vxlan-ovirt_l2-1.0.0.tar.gz
```

Copy the example and edit it for both hosts in the `ovirt_fabric` group.

```bash
cp examples/inventory.yml inventory.local.yml
```

Replace all documentation addresses, select each existing bridge by name and check the public interface against the kernel route to the remote endpoint. The sample tunnel uses UDP 51820 for WireGuard and UDP 4789 inside the tunnel for VXLAN. Set the same WireGuard port, VXLAN port and VNI on both sides.

Run from the controller with both hosts accessible in the same invocation.

```bash
ansible-playbook -i inventory.local.yml wg_to_vxlan.ovirt_l2.site --syntax-check
ansible-playbook -i inventory.local.yml wg_to_vxlan.ovirt_l2.site
ansible-playbook -i inventory.local.yml wg_to_vxlan.ovirt_l2.verify
```

Confirm guest connectivity across the bridges with the test in the operations guide. The same Network and vNIC profile must be available on both oVirt hosts for a guest to retain connectivity after migration. Other oVirt migration requirements, including compatible compute and storage, also apply. [Deployment and verification guide](docs/operations.md)

## Testing the collection

On the controller, create a Python virtual environment, install the controller requirements and run the local build checks.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
bash tests/check.sh
```

The checks exercise the configuration logic, build and install the Galaxy archive and validate the playbooks with synthetic inventory. Deployment, reboot and guest traffic still need to be exercised on a pair of EL9 hosts. Verify both SSH host keys through a trusted channel before the first deployment.

## License

[MIT](LICENSE)
