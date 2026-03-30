# SageMaker Code Editor — Supply Chain & Dependency Confusion Audit
## Final Verified Report

**Target:** https://github.com/aws/sagemaker-code-editor
**Date:** 2026-03-30
**Methodology:** Multi-agent scan → targeted verification → false positive elimination

---

## Executive Summary

10 initial findings were identified across the sagemaker-code-editor repository. After rigorous verification tracing code paths and checking mitigations, **3 validated vulnerabilities** and **3 design risks** remain. **4 findings were eliminated as false positives** (inherited VS Code workflows in a subdirectory that GitHub Actions never executes).

---

## Validated Findings

### V1 — `softprops/action-gh-release@v2` Individual Developer Action
**File:** `.github/workflows/release.yml`
**Verified Severity:** MEDIUM (downgraded from HIGH)
**Category:** GitHub Actions Supply Chain

**What:** The release workflow uses `softprops/action-gh-release@v2` — maintained by individual developer Doug Tangren, tag-pinned not SHA-pinned.

**Attack vector:** Compromise softprops' GitHub account → force-push v2 tag → next AWS release triggers compromised action.

**Impact (verified):**
- Action receives `GITHUB_TOKEN` with `contents: write` only (explicit permissions block)
- Can tamper with release artifacts, push commits, create/delete tags
- **Cannot** access AWS credentials (not configured in this job)
- **Cannot** access other repos (GITHUB_TOKEN scoped to this repo)
- `environment: release` declaration likely provides approval gate

**Mitigations found:**
- Workflow has explicit `permissions: contents: write` (minimal scope)
- `environment: release` may require manual approval
- Tag-only trigger (cannot be triggered via PR)
- CODEOWNERS requires AWS team review

**Recommendation:** Pin to full commit SHA: `softprops/action-gh-release@<40-char-sha>`

---

### V2 — `@emmetio/css-parser` Personal GitHub Fork (Inherited)
**File:** `patched-vscode/extensions/emmet/package.json:485`
**Verified Severity:** LOW-MEDIUM (downgraded from HIGH)
**Category:** Dependency Supply Chain

**What:**
```json
"@emmetio/css-parser": "ramya-rao-a/css-parser#vscode"
```
Personal GitHub fork of a former Microsoft employee (inactive since 2022), pinned to a mutable branch name.

**Key verification findings:**
- **yarn.lock DOES pin to commit SHA** `370c480ac103bd17c7bcfb34bf5d577dc40d3660` via resolved URL
- **No integrity hash** (Yarn v1 limitation for git deps)
- Account `ramya-rao-a` last active 2022-03-04 (dormant 4+ years)
- Pinned commit still matches branch HEAD and tarball is accessible
- **Inherited from upstream Microsoft VS Code** — not introduced by AWS

**Exploitability:**
- NOT directly exploitable with intact lockfile + `--frozen-lockfile`
- BECOMES exploitable if lockfile is regenerated (branch resolves to whatever attacker pushes)
- No integrity hash means no cryptographic verification even with lockfile

**Recommendation:** Replace branch ref with commit SHA in package.json: `"ramya-rao-a/css-parser#370c480ac103bd17c7bcfb34bf5d577dc40d3660"`. Ideally fix upstream in microsoft/vscode.

---

### V3 — `node:20` Container Without Digest Pin
**File:** `.github/workflows/release.yml`
**Verified Severity:** MEDIUM
**Category:** Container Supply Chain

**What:** `container: node:20` without digest pin (`node:20@sha256:...`). The `node:20` tag is mutable.

**Recommendation:** Pin to specific digest: `container: node:20@sha256:<digest>`

---

## Design Risks

### DR1 — Zero SHA-Pinned Actions
**File:** `.github/workflows/release.yml`, `.github/workflows/codebuild-ci.yml`
**Severity:** MEDIUM (Design Risk)

All action references use mutable tags:
- `actions/checkout@v4`
- `aws-actions/configure-aws-credentials@v4`
- `aws-actions/aws-codebuild-run-build@v1`
- `softprops/action-gh-release@v2`

While `actions/*` and `aws-actions/*` are org-maintained (lower individual risk), zero SHA pinning means no immutable guarantees.

### DR2 — 5 SageMaker Extension Names Unregistered on npm
**Files:** `patched-vscode/extensions/sagemaker-*/package.json`
**Severity:** LOW

Five extension packages (`sagemaker-extension`, `sagemaker-idle-extension`, `sagemaker-terminal-extension`, `sagemaker-completion-extension`, `sagemaker-debug-extension`) lack `"private": true` and their names are unregistered on npm.

**Mitigating:** All have empty dependency blocks — `npm install` fetches nothing. Not directly exploitable via build pipeline. Risk is namespace squatting only.

### DR3 — Broad CSP `connect-src` Whitelist
**File:** `patched-vscode/src/vs/server/node/webClientServer.ts:397`
**Severity:** LOW

~20 external domains with wildcards in CSP connect-src. Expands exfiltration surface if XSS is found.

---

## False Positives Eliminated

### FP1 — VS Code Triage Workflows (S6) — FALSE POSITIVE
**Path:** `patched-vscode/.github/workflows/*.yml` (24 files)
**Reason:** These exist under `patched-vscode/.github/workflows/`, NOT the repo root `.github/workflows/`. GitHub Actions only processes workflows at the repository root. These 24 inherited VS Code workflows are **completely inert** — never triggered, never executed. No symlinks or copy mechanisms exist. The secrets they reference (`VSCODE_ISSUE_TRIAGE_BOT_PAT`) are Microsoft's, not configured in the AWS repo.

### FP2 — `npx --yes` Telemetry Extractor (S7) — FALSE POSITIVE
**Path:** `patched-vscode/.github/workflows/telemetry.yml`
**Reason:** Same as FP1 — subdirectory workflow, never executed by GitHub Actions.

### FP3 — Personal Node.js Mirror (S8) — FALSE POSITIVE (for this repo)
**Path:** `patched-vscode/build/azure-pipelines/*.yml`
**Reason:** Azure Pipelines files in `patched-vscode/build/` are VS Code build infrastructure. sagemaker-code-editor does not use Azure Pipelines — its CI uses AWS CodeBuild (`.github/workflows/codebuild-ci.yml`). These files are inherited but unused.

### FP4 — `curl | python` Chromium Tools (S9) — FALSE POSITIVE (for this repo)
**Path:** `patched-vscode/build/azure-pipelines/linux/setup-env.sh`
**Reason:** Same as FP3 — Azure Pipelines infrastructure not used by this repo.

---

## Summary Matrix

| ID | Finding | Verified Severity | Status |
|----|---------|-------------------|--------|
| V1 | softprops/action-gh-release individual dev, tag-pinned | MEDIUM | **VALIDATED** |
| V2 | @emmetio/css-parser personal fork, branch-pinned | LOW-MEDIUM | **VALIDATED** (lockfile mitigates) |
| V3 | node:20 container no digest pin | MEDIUM | **VALIDATED** |
| DR1 | Zero SHA-pinned actions across all workflows | MEDIUM | Design Risk |
| DR2 | 5 extension names unregistered, no private:true | LOW | Design Risk |
| DR3 | Broad CSP connect-src whitelist | LOW | Design Risk |
| FP1 | VS Code triage workflows (mutable ref + PAT) | N/A | **FALSE POSITIVE** (subdirectory) |
| FP2 | npx --yes telemetry extractor | N/A | **FALSE POSITIVE** (subdirectory) |
| FP3 | Personal node-mirror (joaomoreno) | N/A | **FALSE POSITIVE** (unused Azure Pipelines) |
| FP4 | curl\|python Chromium tools | N/A | **FALSE POSITIVE** (unused Azure Pipelines) |

---

## Key Insight

The most important finding in this audit is structural: **sagemaker-code-editor inherits thousands of files from VS Code, but only uses 2 GitHub Actions workflows and AWS CodeBuild for CI/CD.** The vast majority of inherited VS Code build infrastructure (Azure Pipelines, triage workflows, telemetry extractors) is completely inert. Initial scans that flag these without checking execution context will produce many false positives.

The actual attack surface is narrow: 2 active workflows (`release.yml` and `codebuild-ci.yml`) and the dependency tree of `patched-vscode`.
