"""PDF report branding — per-field fallbacks when org white-label values are
empty/null/unset (logo, company name, contact/tagline)."""

from __future__ import annotations

import os
import tempfile

from firewallguard.report import generator as gen


def _minimal_analysis() -> dict:
    return {
        "device": {"model": "TZ670", "serial": "X", "firmware": "7.3.0"},
        "generated_at": "2026-01-01T00:00:00",
        "score": {"score": 50, "grade": "C", "grade_label": "Needs Attention"},
        "findings": [],
        "firmware_intelligence": {"matched_advisories": [], "advisory_count": 0},
    }


# ---- logo fallback ---------------------------------------------------------

def test_default_logo_loads_without_branding():
    """No branding at all → the bundled application logo is used."""
    logo = gen._load_logo(None)
    assert logo is not None
    assert logo["type"] == "svg"
    assert logo["width"] > 0 and logo["height"] > 0


def test_default_logo_loads_with_empty_url():
    logo = gen._load_logo({"logo_url": ""})
    assert logo is not None and logo["type"] == "svg"


def test_default_logo_fallback_on_unusable_url():
    logo = gen._load_logo({"logo_url": "javascript:alert(1)"})
    assert logo is not None and logo["type"] == "svg"


def test_default_logo_file_is_bundled():
    assert os.path.isfile(gen._DEFAULT_LOGO_PATH)


# ---- company-name / title fallback -----------------------------------------

def test_report_title_defaults():
    assert gen._report_title(None, "Executive Report") == "FirewallGuard AI - Executive Report"
    assert gen._report_title({"company_name": None}, "Executive Report") == "FirewallGuard AI - Executive Report"
    assert gen._report_title({"company_name": ""}, "Executive Report") == "FirewallGuard AI - Executive Report"


def test_report_title_custom_company():
    assert gen._report_title({"company_name": "ABC Security"}, "Executive Report") == "ABC Security - Executive Report"


# ---- full PDF builds -------------------------------------------------------

def test_executive_pdf_builds_with_default_branding():
    path = os.path.join(tempfile.mkdtemp(), "exec-default.pdf")
    gen.build_executive_pdf(_minimal_analysis(), path)
    assert os.path.getsize(path) > 1000


def test_executive_pdf_builds_with_partial_branding():
    """Company name empty + tagline set → independent per-field fallback."""
    path = os.path.join(tempfile.mkdtemp(), "exec-partial.pdf")
    gen.build_executive_pdf(_minimal_analysis(), path,
                            {"company_name": "", "contact": "abcsecurity.com"})
    assert os.path.getsize(path) > 1000
