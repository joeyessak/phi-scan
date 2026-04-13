# Migration Ticket Template

Open one tracking issue for the full transfer. Copy this body verbatim.

---

## Title

`Migrate phi-scan from joeyessak/* to phiscanhq/*`

## Body

### Scope

- [ ] `joeyessak/phi-scan` → `phiscanhq/phi-scan`
- [ ] `joeyessak/phi-scan-action` → `phiscanhq/phi-scan-action`

Out of scope: `phi-scan-pro` (does not exist; see
`docs/org-migration-checklist.md` §Scope).

### Pre-flight (§1)

- [ ] Repo cleanliness confirmed (§1.1) — no open PRs, no in-flight CI,
      `main` green
- [ ] Hardcoded-reference sweep reviewed against
      `docs/org-migration-preflight-report.md` §2
- [ ] Current-state snapshot still matches §3 of the pre-flight report
      (ruleset, secrets, variables, environments, webhooks, collaborators)
- [ ] Maintainer checklist `docs/migration/maintainer-checklist.md`
      fully filled in and every row `STATUS: DONE`
- [ ] Draft communications in `docs/migration/communication-draft.md`
      reviewed but **not** published
- [ ] Go / no-go checklist `docs/migration/go-no-go.md` passes

### Transfer (§2 and §3)

- [ ] `phi-scan` transfer initiated
- [ ] `phi-scan` transfer accepted on `phiscanhq`
- [ ] Repo configuration re-applied (§2.2)
- [ ] PyPI token rotated (§2.3)
- [ ] Sigstore bundle verified under new OIDC subject (§2.4)
- [ ] GHCR image pushed to new canonical path (§2.5)
- [ ] Hardcoded-reference sweep round 2 (§2.6)
- [ ] End-to-end validation (§2.7) passes
- [ ] `phi-scan-action` transfer initiated (§3) — **only after** §2.7

### Observation window (§4.2)

- [ ] 48h freeze on new releases unless emergency
- [ ] Daily CI check
- [ ] Ghcr pull counts monitored on old and new paths
- [ ] Issues monitored for redirect or signing failures

### Cleanup (§4.3)

- [ ] Old PyPI token revoked
- [ ] Post-mortem note added to this ticket
- [ ] Legacy ghcr image path schedule set for a future minor release

### Rollback plan

Per `docs/org-migration-checklist.md` §5. Rollback criteria are: CI
broken on `main` with no forward-fix, PyPI publish blocked, Sigstore
verification broken for released artifacts, widespread redirect failure.

### Links

- Runbook: `docs/org-migration-checklist.md`
- Pre-flight report: `docs/org-migration-preflight-report.md`
- Maintainer checklist: `docs/migration/maintainer-checklist.md`
- Go / no-go: `docs/migration/go-no-go.md`
- Communications: `docs/migration/communication-draft.md`

### Labels

`release`, `infra`, `migration`

### Assignees

Repo maintainer.
