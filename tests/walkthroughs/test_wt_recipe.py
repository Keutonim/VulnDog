"""Walkthrough case 1 — custom recipe (docs/VULNERABILITY-DB.md Step 4).

The stranger's path: start from the shipped recipe_stage1.json, change
one knob at a time, pass it with --recipe. This file pins the ACTUAL
validator contract (corpus.validate_recipe) as the corrected docs
describe it: rule-based shape validation with exit 2 + the validator's
reason; extra fields carried; expected_records advisory (operator check
via --dry-run), not a build gate.
"""
from __future__ import annotations

import json

import pytest

from vulndog import cli
from vulndog.engine import corpus as cp

_POP = object()  # sentinel: remove a field from the shipped recipe


@pytest.fixture
def custom_recipe(tmp_path):
    def make(**over):
        r = cp.load_recipe(stage="slice")  # the shipped starting point
        r["recipe_id"] = "stranger-custom"
        for k, v in over.items():
            if v is _POP:
                r.pop(k, None)
            else:
                r[k] = v
        p = tmp_path / f"recipe-{abs(hash(json.dumps(over, default=str)))}.json"
        p.write_text(json.dumps(r, indent=1), encoding="utf-8")
        return str(p)
    return make


def _dry(raw, recipe, tmp_path, capsys, extra=()):
    code = cli.main(["db", "--project", str(tmp_path), "build",
                     "--raw-dir", str(raw), "--recipe", recipe,
                     "--dry-run", *extra])
    out = capsys.readouterr()
    summary = json.loads(out.out) if out.out.strip() else {}
    return code, summary


def test_shipped_recipes_are_valid():
    for stage in ("slice", "full"):
        assert cp.validate_recipe(cp.load_recipe(stage=stage)) == []


def test_valid_custom_recipe_builds(wt_raw, tmp_path, capsys, custom_recipe):
    """Docs Step 4: one knob changed (cvss_min 7.0 -> 8.0) -> accepted."""
    code, summary = _dry(wt_raw, custom_recipe(cvss_min=8.0), tmp_path,
                         capsys)
    assert code == 0, summary.get("message")
    assert summary["records_total"] > 0
    assert summary["message"] == "dry run complete (no store written)"
    assert summary["recipe_id"] == "stranger-custom"


def test_one_knob_has_a_visible_effect(wt_raw, tmp_path, capsys,
                                       custom_recipe):
    """exploit_mirror none drops the mirrored exploit rows."""
    _, base = _dry(wt_raw, custom_recipe(), tmp_path, capsys)
    code, sliced = _dry(wt_raw, custom_recipe(exploit_mirror="none"),
                        tmp_path, capsys)
    assert code == 0
    assert sliced["records_total"] < base["records_total"]
    assert sliced["records_by_kind"].get("exploit", 0) == 0


@pytest.mark.parametrize("over,code_fragment", [
    ({"logic": "bogus"}, "bad_logic"),
    ({"cvss_min": 11}, "bad_cvss_min"),
    ({"cvss_min": True}, "bad_cvss_min"),
    ({"recipe_id": _POP}, "missing:recipe_id"),
    ({"exploit_mirror": "bogus"}, "bad_exploit_mirror"),
    ({"include_reference": {"cwe_web_relevant": True,
                            "cwe_category": False}},
     "bad_include_reference"),
    ({"years": "2024"}, "bad_years"),
    ({"min_total_tokens": -1}, "bad_min_total_tokens"),
    ({"excluded_from_index_veto": "yes"}, "bad_excluded_from_index_veto"),
    ({"stage": ""}, "bad_stage"),
], ids=["logic", "cvss-range", "cvss-bool", "missing-id", "mirror",
        "reference-keys", "years-type", "tokens-negative", "veto-type",
        "stage-empty"])
def test_validator_rejections_fail_loud(wt_raw, tmp_path, capsys,
                                        custom_recipe, over, code_fragment):
    """Wrong shapes -> exit 2 with the validator's reason (never a
    silent build, never a KeyError mid-stream)."""
    code, summary = _dry(wt_raw, custom_recipe(**over), tmp_path, capsys)
    assert code == 2
    msg = summary.get("message", "")
    assert "recipe error" in msg and code_fragment in msg, msg


def test_non_dict_recipe_file_rejected(wt_raw, tmp_path, capsys):
    p = tmp_path / "notdict.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    code, summary = _dry(wt_raw, str(p), tmp_path, capsys)
    assert code == 2
    assert "recipe:not-a-dict" in summary.get("message", "")


def test_extra_fields_are_carried_not_rejected(wt_raw, tmp_path, capsys,
                                               custom_recipe):
    """Corrected docs contract: the validator carries extra fields (the
    shipped recipes themselves carry description/tuning_ruling notes)."""
    code, summary = _dry(wt_raw, custom_recipe(operator_note="hello"),
                         tmp_path, capsys)
    assert code == 0, summary.get("message")


def test_recipe_stage_field_is_metadata(wt_raw, tmp_path, capsys,
                                        custom_recipe):
    """The recipe's stage field is a non-empty-string metadata field
    carried into the manifest; the CLI --stage flag owns the stage
    choice (constrained to slice|full by the parser)."""
    code, summary = _dry(wt_raw, custom_recipe(stage="custom-label"),
                         tmp_path, capsys)
    assert code == 0, summary.get("message")
    assert summary["stage"] == "slice"  # the CLI flag's stage


def test_cli_stage_flag_constrained(wt_raw, tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main(["db", "build", "--raw-dir", str(wt_raw),
                  "--stage", "bogus", "--dry-run"])
    assert exc.value.code == 2


def test_expected_records_is_advisory(wt_raw, tmp_path, capsys,
                                      custom_recipe):
    """Corrected docs contract: expected_records is the operator's
    advisory size window, checked via --dry-run counts — not a build
    gate (the shipped stage-1 tuning_ruling records the manual
    tighten-if-outside procedure)."""
    code, summary = _dry(wt_raw,
                         custom_recipe(expected_records=[10**6, 2 * 10**6]),
                         tmp_path, capsys)
    assert code == 0, summary.get("message")
    lo, hi = 10**6, 2 * 10**6
    assert not (lo <= summary["records_total"] <= hi)  # operator sees this