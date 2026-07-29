import subprocess,sys,tempfile
from pathlib import Path
wheel=Path(sys.argv[1])
with tempfile.TemporaryDirectory() as td:
    v=Path(td)/'venv'; subprocess.check_call([sys.executable,'-m','venv',str(v)])
    py=v/'bin/python'; pip=v/'bin/pip'
    subprocess.check_call([str(pip),'install','--no-deps',str(wheel)])
    subprocess.check_call([str(py),'-m','agentguard','--version'])
