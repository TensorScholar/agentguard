from __future__ import annotations
import ast
from pathlib import Path
ROOT=Path(__file__).parents[1]
findings=[]
for path in (ROOT/'src').rglob('*.py'):
    text=path.read_text(encoding='utf-8')
    if 'shell=True' in text: findings.append(f'{path}: shell=True')
    if 'yaml.load(' in text and 'safe_load' not in text: findings.append(f'{path}: unsafe yaml.load')
    tree=ast.parse(text,path)
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'eval','exec'}:
            findings.append(f'{path}:{node.lineno}: {node.func.id}')
if findings:
    raise SystemExit('\n'.join(findings))
print('static security scan ok')
