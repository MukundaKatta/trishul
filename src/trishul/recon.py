"""Recon target parsing + scope gate.

Before any scan runs, Trishul validates the caller's target list against
their declared engagement scope. This module is that gate: parses CIDRs,
hostnames, and URLs; checks membership against an allowed-scope list;
and emits a structured reason for anything it refuses, so a pentester
can't accidentally hit an adjacent system that wasn't in the contract.

**Only scan systems you are explicitly authorised to test.**
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str                # "ip" | "cidr" | "host" | "url"
    host: str                # hostname or normalised IP
    port: int | None = None
    scheme: str | None = None


@dataclass(frozen=True)
class ScopeDecision:
    target: Target
    allowed: bool
    reason: str


@dataclass(frozen=True)
class EvidenceItem:
    kind: str
    path: str
    summary: str
    sensitivity: str = "internal"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: float
    evidence: tuple[EvidenceItem, ...]
    validation_notes: tuple[str, ...]


def parse_target(raw: str) -> Target | None:
    """Classify a target string. Returns None if we can't parse it."""
    raw = raw.strip()
    if not raw:
        return None
    # URL form
    if "://" in raw:
        p = urlparse(raw)
        if not p.hostname:
            return None
        return Target(raw=raw, kind="url", host=p.hostname.lower(), port=p.port, scheme=p.scheme)
    # CIDR
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return Target(raw=raw, kind="cidr", host=str(net))
        except ValueError:
            return None
    # Bare IP
    try:
        ip = ipaddress.ip_address(raw)
        return Target(raw=raw, kind="ip", host=str(ip))
    except ValueError:
        pass
    # host:port
    host, _, port_s = raw.partition(":")
    port: int | None = None
    if port_s:
        try:
            port = int(port_s)
        except ValueError:
            return None
    if _HOST_RE.match(host):
        return Target(raw=raw, kind="host", host=host.lower(), port=port)
    return None


def parse_scope(scope_entries: Iterable[str]) -> list[Target]:
    """Parse the engagement's allowed-scope list once at load."""
    out: list[Target] = []
    for entry in scope_entries:
        t = parse_target(entry)
        if t is not None:
            out.append(t)
    return out


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    return host == pattern


def check_scope(target: Target, scope: Sequence[Target]) -> ScopeDecision:
    """Is `target` inside any `scope` entry?"""
    # IP / CIDR match
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(target.host)
    except ValueError:
        pass
    for s in scope:
        if s.kind == "cidr" and ip_obj is not None:
            if ip_obj in ipaddress.ip_network(s.host, strict=False):
                return ScopeDecision(target, True, f"in scope CIDR {s.raw}")
        elif s.kind == "ip" and target.host == s.host:
            return ScopeDecision(target, True, f"exact IP match {s.raw}")
        elif s.kind in ("host", "url"):
            if _host_matches(target.host, s.host):
                return ScopeDecision(target, True, f"host match {s.raw}")
    return ScopeDecision(target, False, "no matching scope entry")


def gate(
    targets: Iterable[str],
    scope_entries: Iterable[str],
) -> tuple[list[ScopeDecision], list[str]]:
    """High-level entrypoint: parse both sides and return per-target decisions.

    Returns `(decisions, errors)`; `errors` holds raw inputs we couldn't
    parse, so the CLI can surface them rather than silently skipping.
    """
    scope = parse_scope(scope_entries)
    decisions: list[ScopeDecision] = []
    errors: list[str] = []
    for raw in targets:
        t = parse_target(raw)
        if t is None:
            errors.append(raw)
            continue
        decisions.append(check_scope(t, scope))
    return decisions, errors


def validate_finding(
    finding_id: str,
    title: str,
    severity: str,
    confidence: float,
    evidence: Iterable[EvidenceItem],
    notes: Iterable[str] = (),
) -> Finding:
    bounded_confidence = max(0.0, min(1.0, round(confidence, 3)))
    validation_notes = list(notes)
    if bounded_confidence < 0.6:
        validation_notes.append("Needs manual reviewer confirmation before client delivery.")
    if severity.lower() in {"critical", "high"}:
        validation_notes.append("Confirm exploit path and remediation guidance.")
    return Finding(
        finding_id=finding_id,
        title=title,
        severity=severity.lower(),
        confidence=bounded_confidence,
        evidence=tuple(evidence),
        validation_notes=tuple(dict.fromkeys(validation_notes)),
    )


def build_client_safe_report(findings: Iterable[Finding]) -> dict[str, object]:
    packaged_findings = []
    for finding in findings:
        packaged_findings.append(
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": [
                    {
                        "kind": item.kind,
                        "summary": item.summary,
                    }
                    for item in finding.evidence
                    if item.sensitivity != "restricted"
                ],
                "validation_notes": list(finding.validation_notes),
            }
        )
    return {
        "finding_count": len(packaged_findings),
        "findings": packaged_findings,
        "disclaimer": "Restricted evidence paths have been stripped from this client-safe report.",
    }
