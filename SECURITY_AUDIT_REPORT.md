# GitLab Security Audit Report
## Static Analysis Based on HackerOne Pattern Library

**Date:** 2026-03-05
**Target:** GitLab CE/EE (latest main branch, shallow clone)
**Scope:** High/Critical severity vulnerabilities with verifiable attack paths
**Methodology:** Pattern-driven static analysis informed by 22 HackerOne reports

---

## Executive Summary

After extensive static analysis of the GitLab monorepo using 10+ specialized analysis workers and cross-verification, **no proven high/critical vulnerabilities with complete, verifiable attack paths were identified** in the current codebase snapshot.

GitLab's codebase demonstrates strong defensive programming practices across the major attack surfaces:
- **SSRF**: Consistent use of `Gitlab::HTTP` with `Gitlab::HTTP_V2::UrlBlocker` across all HTTP client call sites
- **Command Injection**: Use of array-based command execution via `Gitlab::Popen` (prevents shell interpretation)
- **Path Traversal**: Consistent use of `Gitlab::PathTraversal.check_path_traversal!` and `check_allowed_absolute_path!`
- **SQL Injection**: Use of Arel parameterization, `sanitize_sql_like`, and hash-based `where` clauses
- **XSS**: Banzai sanitization pipeline, `ERB::Util.html_escape_once` before `html_safe`
- **JWT/Auth**: RSA-based JWT with proper signature verification, HMAC-SHA256 with 32-byte secrets
- **Deserialization**: No instances of `YAML.load` or `Marshal.load` with user-controlled data in production code
- **Import/Export**: Post-extraction symlink cleanup and hard link detection

This reflects significant hardening effort, likely driven by the extensive HackerOne bug bounty program.

---

## Phase 1: Pattern Library from HackerOne Reports

Note: Most H1 reports in the provided list were restricted/non-public. Pattern extraction was limited to publicly available information and general knowledge of GitLab vulnerability classes.

### Known GitLab Vulnerability Patterns (Historical)

| Pattern ID | Category | Root Cause | Typical Sink | GitLab Fix Pattern |
|-----------|----------|------------|--------------|-------------------|
| P-001 | SSRF | Webhook/integration URLs not validated | `Gitlab::HTTP.get/post` | `UrlBlocker.validate!` with DNS rebinding protection |
| P-002 | Path Traversal | Archive extraction without symlink protection | `tar -xf`, `File.read` | `clean_extraction_dir!` post-extraction cleanup |
| P-003 | RCE via Import | Unsafe deserialization of imported YAML/JSON | `YAML.load`, ERB templates | `YAML.safe_load`, allowlisted attributes |
| P-004 | XSS via Markdown | Insufficient sanitization in custom renderers | `html_safe`, `raw()` | Banzai sanitization pipeline, DOMPurify |
| P-005 | AuthZ Bypass | Missing policy checks on new endpoints | Missing `authorize_*` | `before_action` guards, Declarative Policy |
| P-006 | SSRF via Git | Repository import/mirror from internal URLs | `fetch_as_mirror` | `UrlBlocker.validate!` on repository URLs |
| P-007 | CI Config Injection | Variable expansion in CI config | CI YAML includes | Input validation on CI variables |
| P-008 | Command Injection | Shell metacharacters in git operations | `system()`, backticks | Array-based `Gitlab::Popen.popen` |

---

## Phase 2: Static Analysis Results by Worker

### Worker 1-2: ReportMiner-A/B (H1 Pattern Extraction)
- **Result**: Most reports were restricted. Extracted general patterns (see table above).

### Worker 3: RailsRoutes
- **Result**: Route map generated. All controllers reviewed have `before_action` authentication guards.
- Key routes: `config/routes.rb` loads sub-files from `config/routes/`
- All API endpoints use Grape middleware with authentication

### Worker 4: GraphQL
- **Result**: GraphQL mutations consistently use `authorize` declarations
- All mutation classes in `app/graphql/mutations/` inherit from `BaseMutation` which enforces authorization
- No unauthenticated mutations found

### Worker 5: API/REST
- **Result**: Grape API endpoints use `params do ... end` blocks with type coercion
- `order_by` and `sort` parameters are validated through model-level `simple_sorts` hash lookups
- No direct SQL interpolation from API params

### Worker 6: SSRF Specialist
- **Result**: All HTTP client usage reviewed
- `Gitlab::HTTP` wraps all requests with `HTTP_V2::UrlBlocker` (file: `lib/gitlab/http.rb:84-90`)
- Settings-based SSRF protection: `allow_local_requests_from_web_hooks_and_services?`, `dns_rebinding_protection_enabled?`
- Webhook URLs, integration URLs, CI remote includes, LFS downloads, bulk import URLs all pass through URL blocking
- **ActivityPub second-order SSRF**: `subscriber_inbox_url` from external JSON stored and used later (`app/services/activity_pub/accept_follow_service.rb:28`), but `Gitlab::HTTP.post` at the sink applies URL blocking

### Worker 7: Command/RCE Specialist
- **Result**: All command execution uses array-based invocation
- `Gitlab::Popen.popen` (file: `lib/gitlab/popen.rb:77-78`) rejects string commands and single-element arrays with spaces
- `CommandLineUtil` (file: `lib/gitlab/import_export/command_line_util.rb`) uses `%W[]` array syntax for tar commands
- No `system()` with string interpolation found in production code paths

### Worker 8: JWT Bypass
- **Result**: No JWT bypass vulnerabilities found
- `JwtAuthenticatable` (file: `lib/gitlab/jwt_authenticatable.rb:23`) always verifies signatures (`true` parameter)
- CI Job Token uses RSA signing (file: `lib/ci/job_token/jwt.rb:45-47`)
- Jira JWT symmetric decode-without-verify (`lib/atlassian/jira_connect/jwt/symmetric.rb:47`) is used only for ISS claim extraction before full verification at `lib/api/integrations/jira_connect/subscriptions.rb:39`

### Worker 9: Template/XSS Specialist
- **Result**: Extensive `html_safe` usage but consistently preceded by proper escaping
- `ERB.new` with `binding` exists in `app/services/projects/readme_renderer_service.rb:16` but constrained to template directory via path traversal and allowed-path checks
- Banzai markdown pipeline provides sanitization
- `form_helper.rb:27`: `html_escape_once` before `html_safe` - safe pattern
- `sidebars_helper.rb:262`: `message_html.html_safe` on user status - **investigated separately** (see candidates below)

### Worker 10: Path Traversal/LFI Specialist
- **Result**: Consistent path validation across the codebase
- `Gitlab::PathTraversal` (file: `lib/gitlab/path_traversal.rb:12-13`) uses comprehensive regex covering `..`, `/..`, `..\`, URL encoding
- Import/export uses `clean_extraction_dir!` to remove symlinks post-extraction
- CI local includes read from git repository via Gitaly (not filesystem)
- Upload paths use CarrierWave with mount-point-based storage

### Worker 11: SQLi Specialist
- **Result**: No SQL injection from user input found
- All `Arel.sql()` usages use hardcoded strings or model metadata (table_name, column names)
- `where` clauses consistently use parameterized queries
- `find_by_sql` not used with user-controlled input
- `sort_by_attribute` methods use case/when with fixed string sets

### Worker 12: AuthZ Specialist
- **Result**: Comprehensive policy framework
- Declarative Policy system in `app/policies/`
- Controllers use `before_action` for authentication
- `.constantize` calls traced: all class names come from internal model metadata, not user params

### Worker 13: CI/CD Specialist
- **Result**: CI config parsing is well-isolated
- Remote includes validated by `UrlSanitizer.valid?` and `Gitlab::HTTP` URL blocking
- Local includes read from git via Gitaly
- Pipeline config processed through type-checked YAML schema

### Worker 14: Import/Export Specialist
- **Result**: Import/export has extensive protections
- Tar extraction followed by `clean_extraction_dir!` (file: `lib/gitlab/import_export/command_line_util.rb:135-149`)
- Hard link detection and removal
- Symlink detection and removal via `FileInfo.linked?`
- Decompressed archive size validation
- **TOCTOU concern**: Symlinks exist briefly between extraction and cleanup (see candidates)

### Worker 15: Webhooks/Integrations Specialist
- **Result**: URL blocking applied to all outbound requests
- Custom webhook templates use safe JSON serialization (`value.to_json` with quote stripping)
- Token exposed in headers only for configured webhook token field

### Worker 16: Storage Specialist
- **Result**: Object storage uses signed URLs with expiration
- Upload path construction uses CarrierWave mount system

### Worker 17: Background Jobs Specialist
- **Result**: Sidekiq workers receive args from internal code, not directly from user params
- `.constantize` in workers traced to internal model names

### Worker 18: Secrets/Logging Specialist
- **Result**: JWT secrets use 32-byte cryptographic random
- CI job token signing key is RSA-based
- No hardcoded secrets found in production code

### Worker 19: Dependency Audit
- **Result**: No known-vulnerable gem patterns identified in active use
- `YAML.load` only in spec files (not production)
- `Marshal.load(Marshal.dump())` only for deep-copy (internal data, no user input)

---

## Phase 3: Candidate Findings and Verification

### Candidate 1: TOCTOU in Import/Export Tar Extraction
**Status: Needs Confirmation (NOT counted as proven)**

- **Category**: Path Traversal / Arbitrary File Write
- **Location**: `lib/gitlab/import_export/command_line_util.rb:95-98`
- **Description**: The `untar_with_options` method extracts a tar archive and THEN calls `clean_extraction_dir!` to remove symlinks. During extraction, a crafted tar with a symlink followed by a file that traverses through it could write outside the extraction directory before cleanup runs.
- **Why uncertain**:
  1. Modern GNU tar versions (2.x+) have varying behavior on symlink traversal during extraction
  2. Workhorse may pre-process uploads before they reach this code
  3. The import requires admin or elevated privileges
  4. The exact tar version and flags behavior at runtime cannot be determined from static analysis alone
- **If exploitable**: Could lead to arbitrary file write on the server (Critical)
- **Recommended investigation**: Test with a crafted tar containing `symlink -> /tmp/test; file_via_symlink` to verify if GNU tar follows the symlink during extraction

### Candidate 2: User Status `message_html` Stored XSS
**Status: False Positive (Disproven)**

- **Location**: `app/helpers/sidebars_helper.rb:262`
- **Code**: `message_html: user.status&.message_html&.html_safe`
- **Investigation**: The `message_html` field is generated from user status message through the Banzai markdown rendering pipeline, which includes the `SanitizationFilter`. The HTML is sanitized before storage. The `html_safe` call is correct because the content has already been sanitized.
- **Why it's not exploitable**: The Banzai pipeline strips dangerous HTML/JS before the value reaches the database.

### Candidate 3: ActivityPub Second-Order SSRF
**Status: False Positive (Mitigated by URL Blocker)**

- **Location**: `app/services/activity_pub/inbox_resolver_service.rb:17` -> `app/services/activity_pub/accept_follow_service.rb:28`
- **Description**: A remote ActivityPub actor's JSON response sets `subscriber_inbox_url`, which is later used in `Gitlab::HTTP.post`. An attacker could set this to an internal URL.
- **Why it's not exploitable**: `Gitlab::HTTP.post` applies `UrlBlocker` validation, which blocks internal/private IP ranges by default.

### Candidate 4: IDE Schemas Config SSRF (EE)
**Status: False Positive (Mitigated by URL Blocker)**

- **Location**: `app/services/ide/schemas_config_service.rb:41` with EE override `ee/app/services/ee/ide/schemas_config_service.rb:24`
- **Description**: EE extension allows project-defined schema URIs that get fetched via `Gitlab::HTTP.get`
- **Why it's not exploitable**: `Gitlab::HTTP.get` applies URL blocking. Also requires `ide_schema_config` feature to be available.

### Candidate 5: CI Remote Include SSRF
**Status: False Positive (Protected by URL Blocker)**

- **Location**: `lib/gitlab/ci/config/external/file/remote.rb:101`
- **Description**: CI remote includes fetch arbitrary URLs via `Gitlab::HTTP.get`
- **Why it's not exploitable**: URL validation at line 51 (`UrlSanitizer.valid?`), `Gitlab::HTTP` URL blocking, and `BlockedUrlError` handling at line 140.

### Candidate 6: Markdown Include Filter SSRF
**Status: False Positive (Admin-gated + URL Blocker)**

- **Location**: `lib/banzai/filter/include_filter.rb:95`
- **Description**: Wiki/blob markdown includes can fetch HTTP URLs via `Gitlab::HTTP.get`
- **Why it's not exploitable**: Requires admin setting `wiki_asciidoc_allow_uri_includes` to be enabled. `Gitlab::HTTP.get` applies URL blocking.

### Candidate 7: Order-by SQL Injection via API
**Status: False Positive (Model-level validation)**

- **Location**: `lib/api/helpers.rb:556-559`
- **Description**: `params[:order_by]` flows to model `sort_by_attribute` methods
- **Why it's not exploitable**: Model `sort_by_attribute` methods use case/when or hash lookups with fixed allowed values, falling back to default ordering.

### Candidate 8: `constantize` calls with user-influenced data
**Status: False Positive (Internal data only)**

- **Locations**: Multiple workers and services
- **Description**: Several `.constantize` calls on class names
- **Why it's not exploitable**: All traced class names come from internal model metadata (e.g., `issuable.class.name`), not from user input. Sidekiq worker args are enqueued by internal code.

---

## Proven Vulnerabilities

**No proven high/critical vulnerabilities with complete, verifiable attack paths were identified.**

The single "Needs Confirmation" candidate (TOCTOU in tar extraction) requires runtime testing to determine exploitability and would need elevated privileges to trigger.

---

## False Positives Discarded (Summary)

| # | Candidate | Reason for Rejection |
|---|-----------|---------------------|
| 1 | User status `message_html` XSS | Content sanitized by Banzai pipeline before storage |
| 2 | ActivityPub second-order SSRF | `Gitlab::HTTP` URL blocking at the outbound request |
| 3 | IDE Schemas Config SSRF (EE) | URL blocking + feature flag gating |
| 4 | CI Remote Include SSRF | URL validation + URL blocking + error handling |
| 5 | Markdown Include SSRF | Admin-only setting + URL blocking |
| 6 | API order_by SQL injection | Model-level case/when validation with fixed allowed values |
| 7 | `.constantize` code execution | All class names from internal model metadata, not user input |
| 8 | `ERB.new` template injection | Template path constrained to fixed directory with path traversal + allowed-path checks |
| 9 | Custom webhook template injection | `to_json` properly escapes values; template owner already controls webhook destination |
| 10 | JWT `verify_expiration: false` | Only skips expiration (checked separately); signature still verified |
| 11 | Jira JWT decode without verify | Used only for ISS claim extraction; full verification follows |
| 12 | `YAML.load` without safe_load | Only in spec files, not production code |
| 13 | `Marshal.load` | Only used for deep-copy of internal data (`Marshal.load(Marshal.dump(x))`) |

---

## Areas Audited

The following areas were systematically reviewed:

1. **Import/Export**: `lib/gitlab/import_export/`, archive handling, NDJSON parsing
2. **Bulk Imports**: `lib/bulk_imports/`, repository pipeline, URL validation
3. **CI/CD Config**: `lib/gitlab/ci/config/`, includes (local, remote, project, component)
4. **GraphQL**: `app/graphql/mutations/`, `app/graphql/resolvers/`
5. **REST API**: `lib/api/`, Grape endpoints
6. **Webhooks**: `app/services/web_hook_service.rb`, custom templates
7. **Authentication**: JWT handling, job tokens, session management
8. **Markdown Rendering**: `lib/banzai/filter/`, sanitization pipeline
9. **File Uploads**: `app/uploaders/`, multipart handling
10. **Command Execution**: `lib/gitlab/popen.rb`, `CommandLineUtil`
11. **HTTP Clients**: `lib/gitlab/http.rb`, URL blocking
12. **Path Handling**: `lib/gitlab/path_traversal.rb`, upload paths
13. **SQL Queries**: `Arel.sql()` usage, raw SQL patterns, `order_by` handling
14. **Deserialization**: YAML, Marshal, JSON patterns
15. **ActivityPub**: Federation protocol, inbox resolution
16. **IDE Services**: Schema config, terminal config
17. **LFS**: Download service, pointer handling
18. **Dependency Proxy**: External registry URL handling
19. **MCP Tools**: API service URL construction
20. **User Status**: HTML rendering, sanitization

---

## Recommendations

While no proven vulnerabilities were found, the following architectural improvements would further harden the codebase:

1. **Pre-extraction tar validation**: Consider validating tar archive contents (checking for symlinks, absolute paths) BEFORE extraction rather than cleaning up after, to eliminate the TOCTOU window.

2. **Explicit URL allowlists for SSRF-sensitive features**: While `UrlBlocker` is comprehensive, features like ActivityPub federation and CI remote includes could benefit from explicit domain allowlists rather than relying solely on IP-based blocking.

3. **Reduce `html_safe` surface area**: The codebase has many `html_safe` calls. While each individually appears safe, the pattern is error-prone for future development. Consider using Rails' `safe_join` and tag helpers more consistently.

4. **Content Security Policy**: Ensure CSP headers are strict to provide defense-in-depth against any XSS that might bypass server-side sanitization.

---

*Report generated by automated static analysis. All findings are based on code review only. Runtime behavior may differ. "Needs Confirmation" items require dynamic testing.*
