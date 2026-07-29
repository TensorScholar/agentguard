from __future__ import annotations
import re
from pathlib import Path
ROOT=Path(__file__).parents[1]
patterns=[re.compile(r'AKIA[0-9A-Z]{16}'),re.compile(r'sk-[A-Za-z0-9]{20,}'),re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]
violations=[]
for path in ROOT.rglob('*'):
    if not path.is_file() or '.git' in path.parts or path.suffix in {'.pyc','.sqlite','.pem','.whl','.gz','.zip','.bundle'}: continue
    try: text=path.read_text(encoding='utf-8')
    except UnicodeDecodeError: continue
    for pattern in patterns:
        if pattern.search(text): violations.append(f'{path}: {pattern.pattern}')
if violations: raise SystemExit('\n'.join(violations))
print('secret scan ok')
