"""Validate the distribution independently of the source checkout."""
import ast
import json
import re
import sys
import tarfile
from pathlib import PurePosixPath

with tarfile.open(sys.argv[1]) as archive:
    members = {m.name: m for m in archive if m.isfile()}
    manifest = json.loads(archive.extractfile(members['MANIFEST.json']).read())
    assert manifest['collection_info']['namespace'] == 'wg_to_vxlan'
    assert manifest['collection_info']['name'] == 'ovirt_l2'
    for member in members.values():
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        assert not any(p.startswith('.') or p in ('build','dist','__pycache__') for p in path.parts)
        assert path.suffix.lower() not in ('.gz','.pyc','.log','.key','.pass','.pem') and not path.name.endswith('.local.yml')
        data = archive.extractfile(member).read().decode()
        assert not re.search(r'-----BEGIN [A-Z ]*' + r'PRIVATE KEY-----', data), path
        if path.suffix == '.py':
            ast.parse(data, feature_version=(3,9))
        if path.suffix == '.md':
            counterpart = path.name[:-6]+'.md' if path.name.endswith('-ru.md') else path.stem+'-ru.md'
            assert str(path.with_name(counterpart)) in members
    for entry in ['LICENSE','README.md','examples/inventory.yml','playbooks/site.yml','playbooks/verify.yml']:
        assert entry in members
print(f'Distribution contents and bilingual document pairs verified ({len(members)} files).')
