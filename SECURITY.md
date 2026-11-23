# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

This repository has **GitHub private vulnerability reporting enabled**.
To report a security issue, use the **"Report a vulnerability"** button on the
[Security Advisories](../../security/advisories) tab. GitHub keeps your report
private until a fix is coordinated and published.

**Please include:**
- A clear description of the issue
- Steps to reproduce or a minimal proof-of-concept
- The version/commit affected
- Any relevant log output (redact credentials and tokens before submitting)

We aim to acknowledge reports within 72 hours and to publish a coordinated
advisory once a fix is available. Reporters are credited in the fix notes
unless they prefer to stay anonymous.

**Please do not open a public issue for an unfixed vulnerability.**

### Scope

**In scope** (vulnerabilities in VulnDog itself):
- SSRF rail bypass (private/loopback/link-local/metadata/CGNAT filtering)
- Redaction bypass: sensitive values reaching persistent storage
- Scope-pattern bypass: traffic outside configured patterns matched or logged
- MCP tool input validation (`vuln_query`, `highlights`, `run_status`)
- Code execution, path traversal, or privilege escalation via proxy/CLI/MCP
- Supply-chain issues in the build/release pipeline

**Out of scope:**
- Advisory output quality (false positives/negatives are correctness issues,
  not security vulnerabilities — report as a standard bug or discussion)
- Vulnerabilities in Ollama itself or its models
- Issues requiring physical access to the host
- The advisory data store content (maintained upstream)
- Third-party systems you pointed through the proxy

## The tool's own safety model

VulnDog is a passive observer for traffic **you are authorized to test**. The
guarantees and their limits are documented honestly; the short version:

- **Authorized use only.** You are responsible for complying with the laws and
  scopes that apply to what you point through the proxy
  ([README.md](README.md), "Using VulnDog responsibly").
- **Zero target-bound requests.** VulnDog never issues a request of its own
  and never modifies traffic. It observes, matches, and writes candidates
  down — advisory *candidates*, never findings.
- **Safety floors, not security controls.** The scope rail and the
  default-deny SSRF rail refuse out-of-scope and private/loopback/link-local/
  metadata targets before any upstream socket, but they are a floor to build
  on — not a defense to rely on. Known residuals (e.g. the DNS-rebinding
  TOCTOU window) are documented in [README.md](README.md), "Safety posture".
- **Redaction before persist — with documented limits.** Query values are
  length-masked, secret look-alikes replaced, and anything that fails
  redaction is dropped fail-closed. The limits of that guarantee (what can
  still appear in run artifacts) are in
  [docs/RUNS-AND-LOGS.md](docs/RUNS-AND-LOGS.md).
- **Run directories are sensitive.** They contain real target hostnames from
  your traffic. Treat them as sensitive and never redistribute them.
- **No MITM, no cloud LLM.** TLS interception is rejected by design; the only
  model service is a local Ollama embedding endpoint
  ([docs/AI-INTEGRATION.md](docs/AI-INTEGRATION.md)).

## Related documents

- [README.md](README.md) — safety posture, visibility matrix, responsible use
- [docs/RUNS-AND-LOGS.md](docs/RUNS-AND-LOGS.md) — redaction guarantees and limits
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — scope, proxy, and rail configuration
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose a fix