from agentguard.demo import create_demo
from agentguard.adapters.evidence import verify_bundle

def test_demo_builds_all_artifacts(tmp_path):
    out=tmp_path/'demo'; create_demo(out)
    assert (out/'receipt.json').is_file() and (out/'grant.json').is_file()
    assert verify_bundle(out/'evidence')[0]
