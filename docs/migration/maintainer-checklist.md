# Maintainer Migration Checklist — `joeyessak/*` → `phiscanhq/*`

**Companion to:** `docs/org-migration-checklist.md` (runbook),
`docs/org-migration-preflight-report.md` (pre-flight snapshot).

This document is the operational form the maintainer fills in before
initiating the transfer. Every row below must be `STATUS: DONE` with
evidence pasted inline before go / no-go approval is given in §1.6 of the
runbook.

---

## 1. PyPI 2FA confirmation

```
STATUS: DONE
```

**Required:** Confirm the account that owns the `phi-scan` project on
PyPI has 2FA enabled **and** that the 2FA device / recovery codes are
accessible to the maintainer performing the transfer.

Evidence:

```
Maintainer confirmed out-of-band on 2026-04-14 that:
— 2FA is active on the PyPI account that owns the `phi-scan` project
— 2FA device and recovery codes are accessible to the maintainer
  performing the transfer
```

Date confirmed: `2026-04-14`

---

## 2. GHCR pull + digest verification — **Deferred (post-migration hardening)**

```
STATUS: DEFERRED — out-of-scope for migration-go
```

> GHCR container publication is not required for migration-go (PyPI is
> the sole required distribution channel). This section is retained
> for the later post-migration hardening track. See
> [`docs/org-migration-status.md`](../org-migration-status.md).

**Post-migration hardening (not a migration-go gate):** pull the current
canonical container image and record the manifest digest so
post-transfer parity can be verified.

Commands to run (authenticated to ghcr.io):

```bash
docker pull ghcr.io/joeyessak/phi-scan:latest
docker inspect ghcr.io/joeyessak/phi-scan:latest \
  --format '{{index .RepoDigests 0}}'
```

Evidence to paste:

```
PASTE EVIDENCE HERE
— output of `docker inspect ... --format '{{index .RepoDigests 0}}'`
  in the form: ghcr.io/joeyessak/phi-scan@sha256:<64-hex>
```

Date confirmed: `YYYY-MM-DD`

Expected post-transfer digest match: the same image content pushed to
`ghcr.io/phiscanhq/phi-scan:<tag>` must produce the same `sha256:` digest.
Record the post-transfer digest here after §2.5 of the runbook completes.

---

## 3. Sigstore / keyless OIDC verification

```
STATUS: PENDING-UNTIL-SIGNED-RELEASE
```

**Historical gap (recorded 2026-04-15):** The latest release at the time
of this checklist — `v0.5.0`, tagged 2026-04-04 — pre-dates the S11
Sigstore signing step added to `.github/workflows/release.yml` in PR
#123 (commit `7c7a21d`, merged 2026-04-11). Verified by
`git merge-base --is-ancestor 7c7a21d v0.5.0` returning non-zero and
by `gh release view v0.5.0 --json assets` listing only the `.whl` and
`.tar.gz` — no `.sigstore.json` bundle is attached. As a result, no
Sigstore evidence can be captured against `v0.5.0`, and this gate
cannot clear under the current latest release.

**Binding rule:** This gate is bound to the **first S11-signed release
(≥ v0.6.0)**. Evidence below must be captured against that release,
not against `v0.5.0`. Migration-go cannot be approved until this row
is `STATUS: DONE` with evidence from a release whose workflow run
executed the `Sign wheel and sdist with Sigstore (S11)` step.

**Command pack (unchanged; run once a signed release exists).** Replace
`<version>` with the first version ≥ 0.6.0 whose GitHub Release assets
include `phi_scan-<version>-py3-none-any.whl.sigstore.json`:

```bash
gh release download v<version> --repo joeyessak/phi-scan

cosign verify-blob \
  --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle phi_scan-<version>-py3-none-any.whl.sigstore.json \
  phi_scan-<version>-py3-none-any.whl
```

This bundle is the **pre-transfer baseline** whose OIDC subject
(`repo:joeyessak/phi-scan:…`) the post-transfer bundle
(`repo:phiscanhq/phi-scan:…`) will be compared against.

Evidence to paste (after a signed release exists):

```
PASTE EVIDENCE HERE
— released version (must be ≥ 0.6.0 and carry a .sigstore.json asset)
— full `cosign verify-blob` stdout, including the "Verified OK" line
— the OIDC subject embedded in the cert
```

Date confirmed: `YYYY-MM-DD`

---

## 4. Roll-up

Rows §1 (PyPI 2FA) and §3 (Sigstore) must be `STATUS: DONE` before the
maintainer gives the "migration go" approval referenced in §1.6 of the
runbook. Row §2 (GHCR) is **deferred** and is not a migration-go gate.

Row §3 is currently `PENDING-UNTIL-SIGNED-RELEASE`: it cannot clear
until a release ≥ v0.6.0 (the first release built with the S11 signing
step) has been published and its Sigstore bundle verified with the
command pack above.

Signed off by: `MAINTAINER_NAME`
Date: `YYYY-MM-DD`
