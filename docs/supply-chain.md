# PhiScan Supply-Chain Security Policy

**Last reviewed:** 2026-04-14
**Scope:** PhiScan v1.x — the `phi-scan` CLI, the `phi_scan` Python package
published to PyPI, and the GitHub Release artifacts that accompany every
tag.
**Audience:** security reviewers, downstream integrators, and maintainers
operating the release workflow.

This document is the operational policy for the three supply-chain
gates tracked in the [program scorecard](PROGRAM_SCORECARD.md):

- **S9** — Dependency vulnerability scanning in CI.
- **S10** — Software Bill of Materials (CycloneDX SBOM) generation.
- **S11** — Keyless Sigstore signing of release artifacts.

The three gates share a single release story: every wheel and sdist
PhiScan ships to PyPI is built from a dependency closure that has been
audited against the current advisory database (S9), enumerated in a
machine-readable SBOM that travels with the release (S10), and signed
with a verifiable Sigstore bundle anchored in GitHub OIDC (S11).

`docs/threat-model.md` is the threat-oriented view of PhiScan's full
attack surface. This document is scoped to supply-chain controls only
and is the source of truth those scorecard rows point at.

---

## S9 — Dependency Vulnerability Scanning

### Gate behaviour

The `dependency-audit` job in `.github/workflows/ci.yml` runs
`pip-audit` on the production dependency closure exported from the `uv`
lockfile. It executes on every pull request and every push to `main`
and is a required merge check.

The job invokes a single entry point:
`.github/scripts/pip_audit_runner.py`. The runner is responsible for:

1. Loading and validating the policy-enforced ignore list at
   `.pip-audit-ignore.toml` (see [Ignore-list policy](#ignore-list-policy)).
2. Exporting the production dependency set via
   `uv export --quiet --no-hashes --no-dev --format requirements-txt`
   to `pip-audit-requirements.txt` at the repository root. Editable
   install lines (prefixed `-e`) are stripped before pip-audit sees
   them.
3. Running
   `pip-audit --disable-pip --no-deps --strict -r pip-audit-requirements.txt`
   with every accepted advisory ID forwarded as a repeated
   `--ignore-vuln` flag.

The runner exits non-zero on any of the following conditions, and the
CI gate fails the merge:

- The ignore file is missing from the repository root, malformed, or
  contains an entry that violates the policy below.
- The dependency export command fails.
- `pip-audit` reports any vulnerability that is not covered by an
  accepted ignore entry.

### Ignore-list policy

`.pip-audit-ignore.toml` exists even when empty. Every entry is an
explicitly accepted dependency vulnerability; the runner enforces the
rules below before pip-audit is invoked.

```toml
[[ignored]]
id       = "GHSA-xxxx-xxxx-xxxx"   # required — exact advisory ID
reason   = "Upstream fix lands in 2.3.0; no exploit path in our usage"  # required
tracking = "https://github.com/org/repo/issues/123"                     # required
expires  = 2026-07-01             # optional — TOML date literal, must be future-dated
```

**Required fields.** Every entry **must** declare `id`, `reason`, and
`tracking`. Missing any of the three is a hard policy violation.

**Advisory ID format.** `id` must match one of the two canonical
advisory-ID patterns:

- `CVE-YYYY-N+` — e.g. `CVE-2026-34073`.
- `GHSA-xxxx-xxxx-xxxx` — lowercase alphanumerics in three
  four-character groups.

Wildcards are not allowed. Blanket entries are not allowed. Any `id`
that does not match the advisory-ID regex fails the runner before
pip-audit is invoked. No exceptions.

**Reason.** `reason` must be a non-empty string specific enough that a
future auditor can re-evaluate the acceptance decision without
reconstructing context from chat history. "Not exploitable in our
usage" is acceptable only when paired with a tracking link that
explains why.

**Tracking URL.** `tracking` must start with `http://` or `https://`
and point at a GitHub issue, an upstream advisory, or an equivalent
ticket. A tracking URL that does not resolve to a real ticket is a
policy violation in spirit even if the runner does not follow the link.

**Expiry.** `expires`, when set, must be a TOML date literal
(`YYYY-MM-DD`), not a string, and must be in the future. Once the date
has passed, the runner fails the gate on the next run, forcing a
re-review. Entries without `expires` are allowed but must still be
removed as soon as the upstream fix lands.

**Zero entries is the steady state.** The file is intentionally empty
today. The baseline audit on 2026-04-14 resolved every finding via
direct pin bumps in `pyproject.toml` (`cryptography>=46.0.7`,
`pygments>=2.20.0`). New entries should be added only when a fix is
not available or has been judged unsafe to apply, and should be
removed as soon as that is no longer true.

### Running locally

To reproduce the CI audit on a developer machine:

```bash
uv run --python 3.12 python .github/scripts/pip_audit_runner.py
```

The runner writes `pip-audit-requirements.txt` to the repository root
as a side effect. The file is gitignored and may be safely deleted
after the run; CI regenerates it on every invocation.

---

## S10 — CycloneDX SBOM Generation

### What ships with every release

Every GitHub Release attaches `sbom.cyclonedx.json`, a CycloneDX 1.4
Software Bill of Materials enumerating the full production dependency
closure for the tagged build. The SBOM is generated from the exact
same `uv` lockfile state the wheel and sdist were built from, so the
file is a faithful inventory of what a consumer will install when they
`pip install phi-scan==<version>`.

Dev-only dependencies (`dev` group in `pyproject.toml` — ruff, mypy,
pytest, and the tooling behind the CI gates) are **not** included in
the SBOM. The SBOM is a record of what the published artifact carries,
not of the maintainer's development environment.

### Generation flow

The `release` job in `.github/workflows/release.yml` invokes
`.github/scripts/sbom_generator.py` immediately after the built wheel
passes its smoke test and before Sigstore signing. The generator:

1. Exports the production dependency set via the same
   `uv export --quiet --no-hashes --no-dev --format requirements-txt`
   invocation used by the S9 runner.
2. Strips editable install lines and writes the filtered requirements
   to `pip-audit-requirements.txt`.
3. Invokes
   `pip-audit --disable-pip --no-deps --format cyclonedx-json -o sbom.cyclonedx.json -r pip-audit-requirements.txt`
   to produce the SBOM document.
4. Verifies the file was written. A missing output file or a non-zero
   pip-audit exit code fails the release workflow before publish.

The SBOM is attached to the GitHub Release alongside the wheel, sdist,
and Sigstore bundles by the `gh release create` step at the tail of
the workflow.

### Running locally

To regenerate the SBOM for the current working tree:

```bash
uv run --python 3.12 python .github/scripts/sbom_generator.py
```

The output file, `sbom.cyclonedx.json`, is written to the repository
root and is gitignored. It is safe to inspect, diff, or hand to a
downstream consumer for their own audit purposes.

### Format and tooling choice

CycloneDX 1.4 JSON is used because it is the format `pip-audit`
produces natively and the format most downstream SBOM consumers
(Dependency-Track, GitHub's dependency graph, vendor security portals)
accept without conversion. SPDX is a reasonable alternative; the
project does not emit both because a single canonical SBOM is easier
to verify and version.

---

## S11 — Sigstore Keyless Signing

### Signing path

PhiScan uses **keyless Sigstore signing** for every wheel and sdist
published to PyPI. The release workflow invokes
`sigstore/gh-action-sigstore-python@v3.0.0` with the freshly built
`dist/*.whl` and `dist/*.tar.gz` as inputs. The action obtains an
OIDC token from GitHub, submits a signing request to the Sigstore
Fulcio certificate authority, and writes one `<input>.sigstore.json`
bundle per input next to the artifact in `dist/`.

No long-lived signing key exists. The workload identity is the
GitHub Actions OIDC token for the `Release` workflow on this
repository, anchored to the tag that triggered the run. Compromising
a signing key is therefore not a meaningful attack on PhiScan's
release channel; the relevant attack is compromising the GitHub
Actions environment for this repository, which is already the most
sensitive element of the publish path (it holds the PyPI API token).

### What is signed

Exactly the artifacts that are uploaded to PyPI and attached to the
GitHub Release:

- `dist/*.whl` — the built wheel.
- `dist/*.tar.gz` — the source distribution.

The SBOM (`sbom.cyclonedx.json`) is **not** Sigstore-signed. Its
integrity derives from being attached to the same GitHub Release as
the signed artifacts; a consumer who verifies the wheel signature
against the expected workload identity has already trusted the GitHub
Release that carried the SBOM.

### Attaching bundles to the release

The `sigstore/gh-action-sigstore-python@v3.0.0` action has an
`release-signing-artifacts` input that will auto-upload bundles — but
only when the workflow runs on a `release: published` event. The
PhiScan release workflow fires on `push: tags: v*`, so auto-upload
does not apply and the `gh release create` step at the end of the
workflow uploads `dist/*.sigstore.json` explicitly alongside the
wheel, sdist, and SBOM.

### Verifying a release

A downstream consumer can verify a PhiScan release end-to-end with
the `sigstore` CLI:

```bash
# Fetch the artifacts and bundles from the release
gh release download v<version> --repo joeyessak/phi-scan \
    --pattern "*.whl" \
    --pattern "*.tar.gz" \
    --pattern "*.sigstore.json"

# Verify each wheel against the expected GitHub Actions workload identity
sigstore verify github \
    --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
    phi_scan-<version>-py3-none-any.whl
```

The same invocation pattern applies to the sdist. A successful verify
proves the artifact was produced by the PhiScan release workflow on
this repository for the named tag — any attacker who bypasses PyPI
(e.g. via a compromised mirror or a dependency confusion package)
will fail this check.

### What signing does not cover

- **Runtime behaviour.** Sigstore proves an artifact's origin, not its
  correctness. Every release still runs the full CI test suite, the S9
  dependency audit, and the phi-scan self-scan before the wheel is
  built.
- **PyPI metadata.** The package name, description, and classifiers
  rendered on PyPI are not signed. Consumers should verify the wheel,
  not the PyPI UI.
- **The SBOM.** As noted above, the SBOM is trusted transitively
  through the GitHub Release, not directly via Sigstore.

---

## Threat model link-back

Supply-chain compromise is tracked as an out-of-scope item in
`docs/threat-model.md` § 4 ("Out-of-scope threats"). With S9, S10, and
S11 green, the residual risk for that row is bounded to attacks that
bypass the GitHub Actions release workflow itself — compromising the
GitHub OIDC issuer, the Sigstore Fulcio CA, or the maintainer account.
The next threat-model review should move "dependency supply-chain
compromise" from § 4 (out of scope) into § 3 (in scope with named
mitigations) and cite this document as the mitigation location.

---

## Change management

- Any new production dependency added to `pyproject.toml` must pass
  the S9 gate before merge. A pre-existing CVE in a new dependency is
  a merge blocker unless an ignore-list entry is added in the same PR
  with full justification.
- Any change to `.github/scripts/pip_audit_runner.py`,
  `.github/scripts/sbom_generator.py`, or the release workflow's
  signing steps must be called out in the PR description and
  reviewed by a maintainer. These files are part of the trusted
  release path.
- The `Last reviewed` date at the top of this document should be
  updated whenever the policy itself changes, not merely whenever a
  new ignore entry is added or removed.
