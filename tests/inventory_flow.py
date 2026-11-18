"""Run the installed pair preflight in Ansible using synthetic host observations."""
from pathlib import Path
import os
import subprocess
import tempfile

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    for name, text in {
        'ip': """#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:];dev=os.environ['FIXTURE_UPLINK'];addr=os.environ['FIXTURE_PUBLIC']
if 'route' in a: row={'dev':dev, 'prefsrc':addr}
elif 'link' in a: row={'linkinfo':{'info_kind':'bridge'}, 'mtu':1390, 'flags':['UP']}
else: row={'addr_info':[{'local':addr}], 'mtu':1500}
print(json.dumps([row]))
""", 'firewall-cmd': '#!/bin/sh\necho running\n',
    }.items():
        (root/name).write_text(text)
        (root/name).chmod(0o755)
    play = root/'preflight.yml'
    play.write_text("""---
- hosts: ovirt_fabric
  strategy: linear
  gather_facts: false
  connection: local
  environment:
    PATH: "BIN_PATH"
    FIXTURE_UPLINK: "{{ fabric_public_interface }}"
    FIXTURE_PUBLIC: "{{ fabric_public_ipv4 }}"
  vars:
    ansible_facts: {os_family: RedHat, distribution_major_version: '9'}
  tasks:
    - ansible.builtin.import_role:
        name: wg_to_vxlan.ovirt_l2.preflight
        public: true
    - ansible.builtin.assert:
        that:
          - fabric_peer_public_ipv4 != fabric_public_ipv4
          - fabric_peer_wg_address != fabric_wg_address
""".replace('BIN_PATH', str(root)+':'+os.environ['PATH']))
    args = ['ansible-playbook', '-i', 'examples/inventory.yml', '--check', str(play)]
    positive = subprocess.run(args, capture_output=True, text=True)
    if positive.returncode:
        raise RuntimeError(positive.stdout + positive.stderr)
    negative = subprocess.run(args + ['--limit','edge_a'], capture_output=True, text=True)
    assert negative.returncode != 0 and 'ansible_play_hosts_all' in negative.stdout, negative.stdout
    print('Installed collection passed two-host preflight and rejected an incomplete pair.')
