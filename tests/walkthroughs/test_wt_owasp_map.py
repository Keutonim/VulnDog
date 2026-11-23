"""Walkthrough case 2 — OWASP map regen (docs/VULNERABILITY-DB.md Step 5).

The documented door: owasp_map.build_seed_from_top10(zip_path) on a
fresh Top10 drop, fail-loud when an expected edition (2021, 2025) does
not yield exactly 10 category docs. Sample drop synthesized here (10
category docs per edition, each with a 'List of Mapped CWEs' section) —
no network, deterministic.
"""
from __future__ import annotations

import zipfile

import pytest

from vulndog.engine import owasp_map as om

TITLES_2021 = ["Broken Access Control", "Cryptographic Failures", "Injection",
               "Insecure Design", "Security Misconfiguration",
               "Vulnerable and Outdated Components",
               "Identification and Authentication Failures",
               "Software and Data Integrity Failures",
               "Security Logging and Monitoring Failures",
               "Server-Side Request Forgery"]
TITLES_2025 = ["Broken Access Control", "Security Misconfiguration",
               "Software Supply Chain Failures", "Cryptographic Failures",
               "Injection", "Insecure Design", "Authentication Failures",
               "Software or Data Integrity Failures",
               "Logging and Alerting Failures",
               "Mishandling of Exceptional Conditions"]
SAMPLE_CWES = {1: [22, 200, 284], 2: [311, 326, 78], 3: [79, 89, 78],
               4: [284, 639], 5: [16, 611], 6: [200, 522], 7: [287, 306],
               8: [345, 502], 9: [778, 223], 10: [918, 20]}


def make_top10(path, editions=("2021", "2025"), drop_code=None,
               no_section_code=None, extra_edition=None):
    with zipfile.ZipFile(path, "w") as zf:
        for ed in editions:
            titles = TITLES_2021 if ed == "2021" else TITLES_2025
            for i, title in enumerate(titles, start=1):
                code = f"A{i:02d}"
                if drop_code == (ed, code):
                    continue
                stem = title.replace(" ", "_")
                name = f"Top10-master/{ed}/docs/en/{code}_{ed}-{stem}.md"
                body = f"# {code}: {title}\n\nIntro text.\n\n"
                if no_section_code != (ed, code):
                    body += "## List of Mapped CWEs\n\n"
                    body += "\n".join(
                        f"- [CWE-{c}](https://cwe.mitre.org/data/"
                        f"definitions/{c}.html)" for c in SAMPLE_CWES[i])
                    body += "\n\n## References\n\n- ref\n"
                zf.writestr(name, body)
        if extra_edition:
            zf.writestr(f"Top10-master/{extra_edition}/docs/en/"
                        f"A01_{extra_edition}-Old.md",
                        "# Old\n\n## List of Mapped CWEs\n\n"
                        "- [CWE-79](x)\n")
    return str(path)


def test_fresh_drop_regenerates_a_valid_table(tmp_path):
    table = om.build_seed_from_top10(make_top10(tmp_path / "Top10.zip"))
    assert om.validate_table(table) == []
    assert len(table["categories"]) == 20  # 10 per expected edition
    assert table["rows"]
    assert table["source"]["editions"] == ["2021", "2025"]


def test_regenerated_table_matches_the_shipped_shape(tmp_path):
    table = om.build_seed_from_top10(make_top10(tmp_path / "Top10.zip"))
    shipped = om.load_map()
    assert set(table) == set(shipped)
    assert table["map_version"] == shipped["map_version"]
    for cat in table["categories"]:
        assert set(cat) == {"label", "edition", "code", "title", "doc",
                            "cwe_count"}


def test_regeneration_is_deterministic(tmp_path):
    p = make_top10(tmp_path / "Top10.zip")
    assert om.build_seed_from_top10(p) == om.build_seed_from_top10(p)


def test_regenerated_table_serves_lookups(tmp_path):
    table = om.build_seed_from_top10(make_top10(tmp_path / "Top10.zip"))
    cats = om.categories_for_cwe("CWE-79", table)
    assert "A03:2021-Injection" in cats


def test_unexpected_editions_are_ignored_not_fatal(tmp_path):
    p = make_top10(tmp_path / "Top10.zip", extra_edition="2017")
    table = om.build_seed_from_top10(p)
    assert om.validate_table(table) == []
    assert table["source"]["unexpected_editions_ignored"] == ["2017"]


@pytest.mark.parametrize("kwargs,match", [
    ({"drop_code": ("2025", "A07")}, r"edition 2025.*missing.*A07"),
    ({"editions": ("2021",)}, r"edition 2025.*expected 10 category docs"),
    ({"editions": ("2025",)}, r"edition 2021.*expected 10 category docs"),
    ({"no_section_code": ("2021", "A03")},
     r"no 'List of Mapped CWEs' section"),
], ids=["missing-category-doc", "missing-2025-edition",
        "missing-2021-edition", "missing-cwe-section"])
def test_fail_loud_on_layout_drift(tmp_path, kwargs, match):
    """The documented fail-loud law (owasp_map.py:20-23): the tool
    aborts instead of writing a wrong map."""
    p = make_top10(tmp_path / "Top10-bad.zip", **kwargs)
    with pytest.raises(om.OwaspMapError, match=match):
        om.build_seed_from_top10(p)