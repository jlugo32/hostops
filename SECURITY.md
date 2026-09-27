# Security policy

## Reporting
Report vulnerabilities privately via GitHub Security Advisories
(<https://github.com/jlugo32/hostops/security/advisories/new>). Please do not
open a public issue. Expect an acknowledgement within 72 hours.

In scope: anything that lets a caller run a command hostops did not declare,
bypass the confirmation protocol, write outside allowed paths, forge or hide
audit records, or escalate privileges through the shipped sudoers/systemd
files.

## Supported versions
The latest minor release receives fixes.

## Verifying releases
Releases are built by GitHub Actions, signed with cosign (keyless) and carry a
Syft SBOM and a build-provenance attestation:

```bash
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/jlugo32/hostops/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
gh attestation verify hostops_<version>_linux_amd64.tar.gz --repo jlugo32/hostops
```

See [docs/threat-model.md](docs/threat-model.md) for the design.
