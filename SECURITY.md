# Security Policy

## Supported Versions

tunnel-operator is in early development. Security fixes land on `main` and in the `latest` images built from it, and only the latest tagged release receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
<https://github.com/jacaudi/tunnel-operator/security/advisories/new>

If GitHub Security Advisories is unavailable, contact
[@jacaudi](https://github.com/jacaudi) directly via GitHub.

Include what you found, how to reproduce it, and the impact you expect. You will receive an
acknowledgement within 72 hours. We aim to issue a fix or mitigation within 30 days for
high-severity issues; lower-severity issues are addressed on a best-effort basis.

## Scope

In scope:
- The manager (`cmd/manager`) and the agent (`cmd/agent`) binaries and their images.
- The CRDs, RBAC and manifests under `config/`.
- Handling of the server private key and of peer public keys and addresses.
- Anything that lets peer traffic leave the server pod by a path the documentation does not
  describe.

Out of scope:
- WireGuard itself, the kernel module and wireguard-go.
- gluetun, VPN providers, and the cluster's CNI.
- Cluster misconfiguration — Pod Security levels, RBAC granted by an administrator — that does not
  reflect a defect in tunnel-operator itself.
- The upstream [jodevsa/wireguard-operator](https://github.com/jodevsa/wireguard-operator); report
  issues there to its maintainers.
