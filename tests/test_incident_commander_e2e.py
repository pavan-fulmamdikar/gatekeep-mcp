"""Pytest runner for the real-world Incident Commander end-to-end product workflow."""

from examples.incident_commander_e2e import run_all_scenarios


def test_incident_commander_end_to_end() -> None:
    result = run_all_scenarios(verbose=False)
    assert result["stages_passed"] == 6
    assert result["audit_receipts"] >= 15
    assert result["worm_lines"] >= result["audit_receipts"]
