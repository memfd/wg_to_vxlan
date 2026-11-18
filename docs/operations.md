# Deploying and checking a bridge pair

[Русская версия](operations-ru.md) · [Collection overview](../README.md)

## Choose the two endpoints

Copy the example inventory to a local file. Include exactly the two hosts in the `ovirt_fabric` group, including the existing member when extending a network to a new host. Ansible connects to each host over SSH. During deployment each host generates its WireGuard identity locally and Ansible passes the public key to the opposite endpoint. Verify both SSH host keys when setting up the inventory. [Sample inventory](../examples/inventory.yml)

| Setting | How to select it |
|---|---|
| `ansible_host` | An address or name reachable by the controller over SSH. Configure `ansible_user` and privilege escalation for your environment. |
| `fabric_public_ipv4`, `fabric_public_interface` | The public IPv4 endpoint of this host and the local interface used to reach the peer over the public network. |
| `fabric_bridge` | The existing Linux bridge for the selected oVirt VM network on this host. |
| `fabric_wg_address` | A distinct IPv4 address inside the tunnel on each host. Choose addresses outside all routed guest, host and VPN prefixes already in use. |
| `fabric_wg_interface`, `fabric_vxlan_interface` | Names reserved for this link by the administrator on each host. |
| `fabric_wg_port`, `fabric_vxlan_port`, `fabric_vni` | The same values for the two endpoints. WireGuard receives the encrypted datagrams over public IPv4. VXLAN uses its UDP port inside WireGuard. |
| `fabric_wg_mtu`, `fabric_inner_mtu` | Sizes supported by the end-to-end public path and the selected local bridges. |
| `fabric_l2_probe_address` | Optional IPv4 address on the far side of the bridge for a host-originated ping. This check needs a suitable address on the local bridge and a reply path. For a guest-only bridge, test from the guests instead. |

## A fresh server with one public interface

On an enrolled host, select or prepare the guest network using the Engine/VDSM workflow that already owns it. On a fresh server awaiting enrollment, you can bring up an isolated Linux bridge with NetworkManager. The VXLAN port will later join that bridge, so a spare physical NIC is unnecessary. Check that `NetworkManager` and `firewalld` are running, and install the EL9 packages providing `ip`, `nmcli`, `firewall-cmd` and the Python `libnmstate` bindings before starting. Verify the bindings with `/usr/bin/python3 -c 'import libnmstate'`.

The following example creates a **new** persistent, guest-only bridge on the fresh host. Use an unused profile and interface name. The generated locally administered MAC is saved in the profile. Choose the MTU for the actual pair before running these commands. On an enrolled host, use the Engine/VDSM-managed bridge already selected in inventory.

```bash
nmcli -f NAME,TYPE,DEVICE connection show
ip -br link show

bridge_mac=$(python3 -c 'import secrets; print("02:" + ":".join(f"{b:02x}" for b in secrets.token_bytes(5)))')
nmcli connection add type bridge ifname guestlan con-name guestlan \
  ipv4.method disabled ipv6.method disabled bridge.vlan-filtering no \
  802-3-ethernet.cloned-mac-address "$bridge_mac" 802-3-ethernet.mtu 1390
nmcli connection up guestlan
ip -d link show dev guestlan
cat /sys/class/net/guestlan/addr_assign_type
```

Check the bridge's UP flag, MTU, MAC and the value `3` for an explicitly set MAC. An empty bridge can show NO-CARRIER until a port is attached. Set `fabric_bridge: guestlan` in this host's inventory. Before starting guests after enrollment, arrange the same logical network/vNIC profile in Engine through its supported host-network workflow. The Linux bridge by itself does not register that network in Engine. Verify the bridge identity and run the collection's verification again after Engine reconciles the host. [NetworkManager property reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html)

## Prepare the network

1. Attach the VM network to both hosts using the Engine's host network setup or another supported VDSM workflow. Confirm that the selected bridge is a Linux bridge. Identify its ports, MTU and MAC address before adding the tunnel. Verify that the two segments are meant to share broadcasts, including a consistent gateway and DHCP service where present.

   ```bash
   ip -d link show type bridge
   bridge link show
   ```

   Use an UP bridge with VLAN filtering disabled and the exact configured inner MTU. Pin its MAC persistently through the bridge owner, especially for an empty bridge. An automatically selected MAC is accepted only when an existing port already supplies it and attaching the new port preserves it.

2. Check the route to the peer's public IPv4 address on both hosts with `ip -4 route get PEER_IPV4`. The egress device must match the public interface in inventory. The kernel must select the same locally assigned public IPv4 source recorded in inventory. Keep the public uplink separate from the bridge carrying encapsulated guest traffic. The physical or provider network only needs routed IPv4 between the endpoints.

3. Check the public and provider firewall policies in both directions. Allow the **other host's public IPv4 /32** to reach the WireGuard UDP port on each endpoint. The security boundary for guest traffic is the selected L2 network. A guest at the far end gains the same broadcast and Ethernet reachability as a local participant. Review bridge membership and guest network policies accordingly.

4. Measure usable IP MTU on the public path in both directions and give both bridges and guests an appropriate inner MTU. A plain IPv4 WireGuard packet needs 60 bytes of encapsulation space. IPv4 VXLAN with one untagged Ethernet frame needs another 50 bytes. For public path MTU 1500, use WG MTU 1440 and inner IP MTU 1390. Carrying an inner MTU of 1500 without outer fragmentation needs public path MTU of at least 1610. Additional VLAN tags or encapsulation need extra space. A logical network MTU change can affect other guests and hosts on that network, so plan it through oVirt before deployment.

## Apply and verify

With a filled `inventory.local.yml` on the controller, run both playbooks.

```bash
ansible-playbook -i inventory.local.yml wg_to_vxlan.ovirt_l2.site
ansible-playbook -i inventory.local.yml wg_to_vxlan.ovirt_l2.verify
```

Before creating the transport, preflight checks the inventory, egress route and selected bridge on both hosts. The installed profile, overlay files and systemd definitions have specific owners and expected contents. If an existing device, file or unit override conflicts, resolve it before rerunning. Plan changes to an established peer, VNI or bridge as a maintenance cutover using the retirement steps below and a fresh deployment.

The verification playbook checks WireGuard connectivity, firewall rules and the local VXLAN bridge attachment. On each host, use these read-only checks to inspect the layers independently. Replace the interface names if they differ from the example.

```bash
wg show wgfabric0
ip -d link show dev vxfabric0
bridge link show dev vxfabric0
bridge fdb show dev vxfabric0
```

The WireGuard peer should have a recent handshake after traffic is exchanged. The VXLAN device should point to the remote tunnel address, use the expected VNI, and show the intended bridge as its master. A successful WireGuard ping confirms the encrypted IP path. To exercise Ethernet forwarding, attach a test guest on each host to the chosen logical network. Give the guests distinct addresses in one subnet, permit ICMP in their guest policies, ping each other, then inspect `ip neigh` in the guests and the forwarding databases on the hosts. Verify the peer guest's MAC and test in each direction. For inner MTU 1390, an IPv4 ping with `-M do -s 1362` tests a full-sized packet without fragmentation.

The encrypted interface is managed by `wg-quick@INTERFACE.service`. The overlay timer reconciles its VXLAN port after the bridge becomes available, including after VDSM reconfigures the host. Check the timer with `systemctl status wg-to-vxlan-overlay-vxfabric0.timer` for the sample interface name. After a planned reboot or Engine network change, run `verify` and repeat the guest test. Before using guest migration as a test, first establish ordinary guest connectivity across the link.

## Localizing a problem

| Observation | What to inspect |
|---|---|
| No WireGuard handshake after a ping | Endpoint addresses, public routing and return path, public UDP permissions at both hosts and any provider firewall. |
| WireGuard exchanges packets but guests cannot discover one another | VXLAN local/remote tunnel addresses, VNI and destination port, firewall on the WG interface, bridge master and vNIC network on both sides. |
| Small pings work but large traffic stalls | Compare actual link MTUs, public path MTU in both directions and guest MTUs. Repeat the DF test from the guests. |
| Traffic disappears after host network reconfiguration | Check that the intended bridge exists with its original name, inspect systemd unit status and check the actual VXLAN attachment. |
| Unexpected ARP, duplicate DHCP replies or a broadcast storm | Check for a second L2 path, a duplicate address, or a second DHCP/gateway service on the joined segment. |

## Retiring a link

If a previous collection namespace already manages this link, follow the retirement procedure with that version before deploying the renamed collection. Its host files, systemd units and interface ownership markers use different names.

Move guests that use the link to another path or arrange a maintenance window. Record the interface names, owned units, public firewall grant and the active inventory. Stop and disable the per-link overlay timer, and stop its service before removing its owned VXLAN port. Then disable the WireGuard service for this pair, retire its configuration and dedicated firewall grants, and verify ordinary traffic on the original host bridges. Retain or remove the dedicated private key according to your key retention policy. A rebuild using the same peer identity requires that key. An owned WireGuard profile with different settings requires a planned cutover. On both hosts, review other users of the public UDP port or firewall zone before removing a shared rule.
