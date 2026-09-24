import importlib.util
import json
from pathlib import Path


def test_portfolio_demo_runs_complete_improvement_loop(tmp_path: Path, monkeypatch, capsys) -> None:
    script = Path(__file__).parents[1] / "scripts" / "portfolio_demo.py"
    spec = importlib.util.spec_from_file_location("portfolio_demo", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.chdir(tmp_path)

    module.main()

    before = json.loads((tmp_path / "demo-output" / "before.json").read_text(encoding="utf-8"))
    after = json.loads((tmp_path / "demo-output" / "after.json").read_text(encoding="utf-8"))
    assert before["risk_score"]["overall_risk_score"] == 35
    assert after["risk_score"]["overall_risk_score"] == 10
    assert before["overall_compliance"]["non_compliant_rules"] == 2
    assert after["overall_compliance"]["non_compliant_rules"] == 1
    assert (tmp_path / "demo-output" / "before.csv").exists()
    assert (tmp_path / "demo-output" / "after.html").exists()
    output = capsys.readouterr().out
    assert "Remediation: succeeded verified= True" in output
    assert "Improved compliance: 19/20" in output
