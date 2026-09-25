"""Sentinel canonical vulnerability taxonomy.

Engines label issues in their own vocabularies (ZAP plugin ids, template ids,
free text). Correlation needs one vocabulary, so every observation is mapped to
a canonical class here, primarily through CWE ids. Keeping this table in one
place is what lets engines be swapped without touching correlation or reports.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnClass:
    key: str
    title: str
    cwes: frozenset[int]
    owasp_2021: tuple[str, ...]


def _vc(key: str, title: str, cwes: set[int], *owasp: str) -> VulnClass:
    return VulnClass(key=key, title=title, cwes=frozenset(cwes), owasp_2021=tuple(owasp))


A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"
A08 = "A08:2021-Software and Data Integrity Failures"
A09 = "A09:2021-Security Logging and Monitoring Failures"
A10 = "A10:2021-Server-Side Request Forgery"

OTHER = "other"

CLASSES: tuple[VulnClass, ...] = (
    _vc("xss", "Cross-Site Scripting", {79, 80, 83, 87}, A03),
    _vc("sql_injection", "SQL Injection", {89, 564}, A03),
    _vc("nosql_injection", "NoSQL Injection", {943}, A03),
    _vc("command_injection", "OS Command Injection", {77, 78}, A03),
    _vc("code_injection", "Code Injection", {94, 95}, A03),
    _vc("template_injection", "Server-Side Template Injection", {1336}, A03),
    _vc("ldap_injection", "LDAP Injection", {90}, A03),
    _vc("xpath_injection", "XPath Injection", {643}, A03),
    _vc("header_injection", "HTTP Header Injection", {93, 113}, A03),
    _vc("path_traversal", "Path Traversal", {22, 23, 35, 36}, A01),
    _vc("ssrf", "Server-Side Request Forgery", {918}, A10),
    _vc("xxe", "XML External Entity Processing", {611, 776}, A05),
    _vc("open_redirect", "Open Redirect", {601}, A01),
    _vc("csrf", "Cross-Site Request Forgery", {352}, A01),
    _vc("broken_object_authz", "Broken Object Level Authorization", {639}, A01),
    _vc("broken_access_control", "Broken Access Control", {284, 285, 862, 863}, A01),
    _vc("authentication", "Authentication Weakness", {287, 306, 307, 521, 1391}, A07),
    _vc("session_management", "Session Management Weakness", {384, 613}, A07),
    _vc("insecure_cookie", "Insecure Cookie Attributes", {614, 1004, 1275}, A05),
    _vc("secret_exposure", "Exposed Secret or Credential", {798, 312, 540}, A07),
    _vc("information_disclosure", "Information Disclosure", {200, 209, 359, 532, 538}, A01),
    _vc("directory_listing", "Directory Listing", {548}, A05),
    _vc("debug_exposure", "Debug or Diagnostic Interface Exposed", {215, 489}, A05),
    _vc("missing_security_header", "Missing or Weak Security Header", {693}, A05),
    _vc("clickjacking", "Clickjacking", {1021}, A04),
    _vc("cors_misconfiguration", "CORS Misconfiguration", {942, 346}, A05),
    _vc("tls_weakness", "TLS / Transport Weakness", {295, 319, 326, 327}, A02),
    _vc("vulnerable_component", "Vulnerable or Outdated Component", {937, 1035, 1104}, A06),
    _vc("insecure_deserialization", "Insecure Deserialization", {502}, A08),
    _vc("unrestricted_upload", "Unrestricted File Upload", {434}, A04),
    _vc("security_misconfiguration", "Security Misconfiguration", {16, 1188}, A05),
    _vc(OTHER, "Other", set()),
)

BY_KEY: dict[str, VulnClass] = {c.key: c for c in CLASSES}

_BY_CWE: dict[int, VulnClass] = {}
for _c in CLASSES:
    for _cwe in _c.cwes:
        if _cwe in _BY_CWE:  # pragma: no cover - guarded by tests
            raise RuntimeError(f"CWE-{_cwe} mapped twice")
        _BY_CWE[_cwe] = _c


def class_for_cwe(cwe: int) -> VulnClass | None:
    return _BY_CWE.get(cwe)


def classify(cwes: list[int] | None = None, hint: str | None = None) -> VulnClass:
    """Resolve a canonical class from CWE ids, falling back to an explicit hint.

    The first CWE that maps wins; an explicit ``hint`` that names a canonical
    class key is used when no CWE maps. Unknown input yields ``other``.
    """
    for cwe in cwes or []:
        found = _BY_CWE.get(cwe)
        if found is not None:
            return found
    if hint and hint in BY_KEY:
        return BY_KEY[hint]
    return BY_KEY[OTHER]


def owasp_for(key: str) -> list[str]:
    vc = BY_KEY.get(key)
    return list(vc.owasp_2021) if vc else []
