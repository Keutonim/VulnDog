"""vulndog.engine -- vendored vuln_watchdog engine (ADR-1).

Upstream: the upstream project's vuln_watchdog (offline vuln-KB export +
hunt watchdog tooling). Module names are kept identical to upstream; the
F4 redaction import is replumbed to the vendored ``_redaction_core``
module (ADR-1d) -- no upstream package is imported at runtime.
Loopback-only; pure stdlib. See VENDORING.md.
"""
