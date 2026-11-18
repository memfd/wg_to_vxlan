#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
temp_dir=$(mktemp -d)
trap 'rm -rf -- "$temp_dir"' EXIT
export ANSIBLE_COLLECTIONS_PATH="$temp_dir/collections"
export ANSIBLE_LOCAL_TEMP="$temp_dir/ansible-tmp"
python3 -m unittest discover -s tests -p 'test_*.py'
mkdir -p dist
ansible-galaxy collection build --output-path dist --force
artifact=dist/wg_to_vxlan-ovirt_l2-1.0.0.tar.gz
ansible-galaxy collection install "$artifact" --no-deps -p "$ANSIBLE_COLLECTIONS_PATH"
for play in site verify; do
  ansible-playbook -i examples/inventory.yml "wg_to_vxlan.ovirt_l2.$play" --syntax-check
done
python3 tests/inventory_flow.py
python3 tests/inspect_release.py "$artifact"
(cd dist && sha256sum "${artifact#dist/}" > SHA256SUMS)
