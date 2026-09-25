"""Scope engine: the authoritative decision on whether a URL may be touched.

Every request an engine wants to make is checked here first. The rules:

* The target must carry a valid authorization record (checked by the caller,
  re-asserted here defensively).
* Exclude rules always beat include rules.
* Nothing outside the include set is in scope.
* Private/loopback/link-local address literals are refused unless a rule opts
  into them explicitly (guards against SSRF-style scope escapes and accidental
  scanning of internal infrastructure).

The engine is pure and synchronous so it can be unit-tested exhaustively and
reused inside the egress proxy.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from vantage.domain.target import ScopeRule, ScopeRuleKind, Target

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: int | None = None


@dataclass(frozen=True)
class _ParsedUrl:
    scheme: str
    host: str
    port: int
    path: str
    method: str | None


def _parse(url: str, method: str | None) -> _ParsedUrl | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port or _DEFAULT_PORTS.get(scheme, 0)
    except ValueError:
        return None
    if port == 0:
        return None
    return _ParsedUrl(scheme, host, port, parts.path or "/", method.upper() if method else None)


def _host_matches(rule_host: str, host: str) -> bool:
    if rule_host == host:
        return True
    if rule_host.startswith("*."):
        suffix = rule_host[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix[1:]
    # CIDR / IP rule against an IP host.
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    try:
        if "/" in rule_host:
            return addr in ipaddress.ip_network(rule_host, strict=False)
        return addr == ipaddress.ip_address(rule_host)
    except ValueError:
        return False


def _is_private_literal(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _rule_allows_private(rule: ScopeRule) -> bool:
    # A rule whose host is itself a private literal/CIDR is an explicit opt-in.
    return _is_private_literal(rule.host) or "/" in rule.host


class ScopeEngine:
    def __init__(self, target: Target) -> None:
        self._rules = list(target.scope_rules)
        self._authorized = target.is_authorized()
        self._private_optin = any(_rule_allows_private(r) for r in self._rules)

    @classmethod
    def from_rules(cls, rules: list[ScopeRule], *, authorized: bool = True) -> ScopeEngine:
        """Build directly from rules, e.g. from an EngineRunRequest.

        ``authorized`` should reflect that the orchestrator already verified the
        target's authorization before dispatching the engine; scope checks then
        only enforce the include/exclude/private-address rules.
        """
        obj = cls.__new__(cls)
        obj._rules = list(rules)
        obj._authorized = authorized
        obj._private_optin = any(_rule_allows_private(r) for r in rules)
        return obj

    def _rule_matches(self, rule: ScopeRule, u: _ParsedUrl) -> bool:
        if u.scheme not in rule.schemes:
            return False
        if not _host_matches(rule.host, u.host):
            return False
        if rule.ports is not None:
            if u.port not in rule.ports:
                return False
        elif u.port != _DEFAULT_PORTS.get(u.scheme, -1):
            return False
        if not u.path.startswith(rule.path_prefix):
            return False
        if rule.path_regex is not None and not re.search(rule.path_regex, u.path):
            return False
        return not (
            rule.methods is not None and u.method is not None and u.method not in rule.methods
        )

    def check(self, url: str, method: str | None = None) -> ScopeDecision:
        if not self._authorized:
            return ScopeDecision(False, "target has no valid authorization record")

        u = _parse(url, method)
        if u is None:
            return ScopeDecision(False, f"unparseable or portless url: {url!r}")

        if _is_private_literal(u.host) and not self._private_optin:
            return ScopeDecision(
                False, f"private/loopback address {u.host} not explicitly in scope"
            )

        # Exclude rules first: any match refuses.
        for idx, rule in enumerate(self._rules):
            if rule.kind is ScopeRuleKind.EXCLUDE and self._rule_matches(rule, u):
                return ScopeDecision(False, f"excluded by rule #{idx}", idx)

        for idx, rule in enumerate(self._rules):
            if rule.kind is ScopeRuleKind.INCLUDE and self._rule_matches(rule, u):
                return ScopeDecision(True, f"included by rule #{idx}", idx)

        return ScopeDecision(False, "not covered by any include rule")

    def allows(self, url: str, method: str | None = None) -> bool:
        return self.check(url, method).allowed


def default_scope_rules_for(target: Target) -> list[ScopeRule]:
    """Derive a conservative include rule per base URL when none are supplied:
    same host, same scheme, same directory prefix."""
    rules: list[ScopeRule] = []
    for base in target.base_urls:
        parts = urlsplit(str(base))
        if not parts.hostname:
            continue
        scheme = (parts.scheme or "https").lower()
        prefix = parts.path if parts.path.endswith("/") else parts.path.rsplit("/", 1)[0] + "/"
        rules.append(
            ScopeRule(
                kind=ScopeRuleKind.INCLUDE,
                host=parts.hostname,
                schemes=[scheme],
                ports=[parts.port] if parts.port else None,
                path_prefix=prefix or "/",
            )
        )
    return rules
