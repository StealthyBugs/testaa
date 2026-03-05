# GitLab Security Audit Report
## Static Analysis Based on HackerOne Pattern Library

**Date:** 2026-03-05
**Target:** GitLab CE/EE (latest main branch, shallow clone)
**Scope:** High/Critical severity vulnerabilities with verifiable attack paths
**Methodology:** Pattern-driven static analysis informed by 22 HackerOne reports

---

## Executive Summary

After extensive static analysis of the GitLab monorepo using 20+ specialized analysis workers and cross-verification, **no proven high/critical vulnerabilities with complete, verifiable attack paths were identified** in the current codebase snapshot. Several medium-confidence candidates were identified that warrant further investigation through dynamic testing.

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
- **Result**: All HTTP client usage reviewed (22 distinct sink locations mapped)
- `Gitlab::HTTP` wraps all requests with `HTTP_V2::UrlBlocker` (file: `lib/gitlab/http.rb:84-90`)
- Settings-based SSRF protection: `allow_local_requests_from_web_hooks_and_services?`, `dns_rebinding_protection_enabled?`
- Webhook URLs, integration URLs, CI remote includes, LFS downloads, bulk import URLs all pass through URL blocking
- **ActivityPub second-order SSRF**: `subscriber_inbox_url` from external JSON stored and used later (`app/services/activity_pub/accept_follow_service.rb:28`), but `Gitlab::HTTP.post` at the sink applies URL blocking
- **Jenkins integration**: Uses `addressable_url: true` validator instead of `public_url: true`, which allows localhost/local network by default (see Candidate 9)
- **CI remote include cache**: Cross-project cache keyed only on URL when `ci_cache_remote_includes` feature flag enabled (see Candidate 10)

### Worker 7: Command/RCE Specialist
- **Result**: All production command execution uses array-based invocation
- `Gitlab::Popen.popen` (file: `lib/gitlab/popen.rb:77-78`) rejects string commands and single-element arrays with spaces
- `CommandLineUtil` (file: `lib/gitlab/import_export/command_line_util.rb`) uses `%W[]` array syntax for tar commands
- No `system()` with string interpolation found in production code paths
- No `exec()`, no backtick execution with user input, no `Terrapin::CommandLine` usage found
- **Tooling-only variants**: `tooling/lib/tooling/predictive_tests/mapping_fetcher.rb:132` uses `Open3.capture3("gzip -d -c #{archive} > #{file_path}")` with string interpolation -- not production code but a shell injection risk in CI tooling
- **Script variant**: `scripts/lint/validate_fast_spec_helper_usage.rb:55-57` interpolates `target_branch` into shell string -- CI script context only

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

### Worker 20: H1 Pattern Verification
- **Result**: All 6 tested historical H1 vulnerability patterns verified as properly fixed
- **Command Injection (H1 #1609965)**: `DecompressedGzipSizeValidator` now uses array-form `Open3.pipeline_r` -- fixed
- **Git Flag Injection (H1 #658013/#653125)**: Git operations migrated to Gitaly (gRPC) -- architectural fix
- **UploadsRewriter Path Traversal (H1 #827052)**: Multi-layer defense: `check_path_traversal!`, `check_allowed_absolute_path!`, `File.realpath` prefix check -- fixed
- **DesignReferenceFilter XSS (H1 #1212067)**: `write_opening_tag` uses `CGI.escapeHTML` for all attribute values (`lib/banzai/filter/concerns/html_writer.rb:32`) -- fixed
- **Kramdown RCE (H1 #1125425)**: Kramdown 2.5.1 includes upstream CVE-2021-28834 fix -- fixed (no app-level `forbidden_inline_options` blocklist, relies on gem version)
- **FogBugz SSRF (H1 #1092230)**: No `Kernel.open`/`URI.open` in production; download service has strict domain allowlist `*.fogbugz.com` -- fixed

### Worker 21: Frontend XSS Specialist
- **Result**: Reviewed `v-html` usage in Vue components and `raw()`/`html_safe` in ERB templates
- `app/views/projects/network/show.json.erb`: Uses `raw(data.to_json)` but safe because `config.active_support.escape_html_entities_in_json = true` (`config/application.rb:270`)
- DOMPurify configured with `ALLOW_UNKNOWN_PROTOCOLS: true` (`app/assets/javascripts/lib/dompurify.js:29`) -- allows `tel:`, `ssh:` etc. but DOMPurify always blocks `javascript:`, `data:`, `vbscript:` regardless
- `v-html` in diff components (`app/assets/javascripts/diffs/components/diff_row.vue:294,416`) renders server-sanitized content
- No server-side template injection found; all `ERB.new` calls use hardcoded file paths

### Worker 22: Multipart Upload / Workhorse Specialist
- **Result**: Reviewed multipart upload JWT handling and file processing
- Multipart JWTs use HMAC-SHA256 with 256-bit secret, signature always verified
- `UploadedFile` validates paths with `File.realpath` + prefix-based allowlist (`lib/gitlab/middleware/uploaded_file.rb:62-66`)
- CarrierWave callback checks all path components for `..` traversal before caching
- **Minor**: Multipart upload JWTs have no `exp` claim -- captured tokens theoretically replayable (Low severity, requires secret knowledge or MITM)

### Worker 23: LFS / Dependency Proxy / Package Registry
- **Result**: Defense-in-depth across all examined paths
- LFS downloads use `PublicUrlValidator` + `Gitlab::HTTP` URL blocking
- Dependency proxy uses `Gitlab::HTTP` with Workhorse `ssrf_filter` behind `dependency_proxy_for_containers_ssrf_protection` feature flag
- Object storage: signed URLs with 4h15m expiry, path traversal checks via `Pathname.cleanpath` + prefix validation
- NuGet remote metadata uses JWT-signed URLs via `Gitlab::HTTP`

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

### Candidate 9: Jenkins Integration SSRF via `addressable_url` Validator
**Status: Needs Confirmation (NOT counted as proven)**

- **Category**: SSRF
- **Location**: Jenkins integration model uses `addressable_url: true` validator instead of `public_url: true`
- **Description**: The `addressable_url` validator allows localhost and local network addresses by default, unlike `public_url: true` which blocks them. A project maintainer could configure the Jenkins integration URL to point to internal services (e.g., `http://127.0.0.1:8080/`, `http://169.254.169.254/`).
- **Why uncertain**:
  1. `Gitlab::HTTP` URL blocking still applies at request time, which may independently block internal IPs
  2. Integration configuration requires project maintainer role
  3. The `allow_local_requests_from_web_hooks_and_services?` admin setting controls runtime behavior
- **If exploitable**: SSRF to internal services from any project maintainer (Medium)
- **Recommended investigation**: Verify whether `Gitlab::HTTP` runtime URL blocking independently prevents requests to internal IPs when the URL passes `addressable_url` validation

### Candidate 10: CI Remote Include Cross-Project Cache Poisoning
**Status: Needs Confirmation (NOT counted as proven)**

- **Category**: CI Config Injection
- **Location**: CI remote include caching (when `ci_cache_remote_includes` feature flag enabled)
- **Description**: When the feature flag is enabled, remote CI includes are cached keyed only by URL. If two unrelated projects reference the same remote include URL, one project's cached response could be served to another. An attacker who controls the remote URL could serve different content on first vs subsequent requests.
- **Why uncertain**:
  1. Requires `ci_cache_remote_includes` feature flag to be enabled
  2. The cache TTL and scope need runtime verification
  3. Both projects would need to reference the same URL
- **If exploitable**: Cross-project CI configuration injection (Medium-High)

### Candidate 11: Legacy Marshal Deserialization in ActiveSession
**Status: Needs Confirmation (NOT counted as proven)**

- **Category**: Unsafe Deserialization
- **Location**: `app/models/active_session.rb:250`
- **Description**: Legacy code path uses `Marshal.load` to deserialize session data from Redis. If an attacker can write arbitrary data to the Redis session store, this could lead to RCE via Ruby gadget chains.
- **Why uncertain**:
  1. Redis access requires compromising the Redis instance itself (network-level attack)
  2. This appears to be a legacy compatibility path
  3. Session data is normally written by the application, not by users directly
- **If exploitable**: RCE via Ruby deserialization gadget chains (Critical, but requires Redis compromise)

### Candidate 12: HelpController Path Traversal (Single-Layer Defense)
**Status: Needs Confirmation (NOT counted as proven)**

- **Category**: Path Traversal / LFI
- **Location**: `app/controllers/help_controller.rb:38-46`
- **Description**: The `show` action uses `clean_path_info` to sanitize the path parameter, then uses `File.join(Rails.root, 'doc', path)` followed by `send_file`. The defense relies solely on `clean_path_info` without an `expand_path` prefix check.
- **Why uncertain**:
  1. `clean_path_info` removes `..` sequences, which is the primary traversal vector
  2. `File.join` with `Rails.root` constrains the base directory
  3. The path flows through Rails routing which may impose additional constraints
- **If exploitable**: Read arbitrary files on the server (High)
- **Recommended investigation**: Test with URL-encoded or double-encoded traversal sequences against `clean_path_info`

---

## Proven Vulnerabilities

**No proven high/critical vulnerabilities with complete, verifiable attack paths were identified.**

Four "Needs Confirmation" candidates were identified that require dynamic testing:

| # | Candidate | Potential Severity | Blocker for Proof |
|---|-----------|-------------------|-------------------|
| 1 | TOCTOU in tar extraction | Critical (arbitrary file write) | Requires runtime tar behavior testing; elevated privileges needed |
| 9 | Jenkins integration SSRF | Medium (SSRF to internal services) | Need to verify runtime URL blocking independence from validator |
| 10 | CI remote include cache poisoning | Medium-High (cross-project config injection) | Requires `ci_cache_remote_includes` feature flag; cache behavior needs runtime verification |
| 11 | Legacy Marshal deserialization | Critical (RCE) | Requires Redis compromise as prerequisite |
| 12 | HelpController path traversal | High (LFI) | Need to verify `clean_path_info` against encoded traversal sequences |

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
| 14 | `v-html` in diff components | Server-sanitized content rendered via Banzai + DOMPurify double sanitization |
| 15 | DOMPurify `ALLOW_UNKNOWN_PROTOCOLS` | Only allows custom protocols like `tel:`, `ssh:`; `javascript:` always blocked by DOMPurify |
| 16 | `raw()` in `show.json.erb` | `escape_html_entities_in_json = true` ensures `.to_json` escapes `<`, `>`, `&` |
| 17 | Webhook log stores interpolated URL | URL variables stored in `WebHookLog` via `interpolated_url` -- by design, webhook owner controls destination |
| 18 | Multipart upload JWT no expiration | Low severity; requires capturing JWT which needs secret knowledge or MITM |
| 19 | Kramdown no app-level `forbidden_inline_options` | Fix relies on upstream gem version (2.5.1); gem downgrade would re-expose CVE-2021-28834 |
| 20 | `Oj.load` with `:rails` mode on env vars | `lib/gitlab/fp/settings/env_var_override_processor.rb:98` -- env vars not user-controlled |
| 21 | `ci/namespace_mirror.rb` dynamic SQL | Values are properly quoted; RuboCop suppression documented |
| 22 | Tooling shell injection | `tooling/lib/tooling/predictive_tests/mapping_fetcher.rb:132` -- not production code |

---

## H1 Historical Pattern Verification

All 6 tested historical HackerOne vulnerability patterns have been verified as properly fixed:

| H1 Report | Vulnerability | Fix Status | Evidence |
|-----------|--------------|------------|----------|
| #1609965 | Command injection in `DecompressedGzipSizeValidator` | **Fixed** | Now uses array-form `Open3.pipeline_r` (`lib/gitlab/ci/decompressed_gzip_size_validator.rb:30`) |
| #658013 / #653125 | Git flag injection via user refs | **Fixed** | Git operations migrated to Gitaly (gRPC); no shell-based git in production |
| #827052 | UploadsRewriter path traversal | **Fixed** | Multi-layer: `check_path_traversal!` + `check_allowed_absolute_path!` + `File.realpath` prefix check |
| #1212067 | DesignReferenceFilter XSS | **Fixed** | `write_opening_tag` escapes all attributes via `CGI.escapeHTML` (`lib/banzai/filter/concerns/html_writer.rb:32`) |
| #1125425 | Kramdown inline options RCE | **Fixed** | Kramdown 2.5.1 includes CVE-2021-28834 fix; spec tests verify formatter rejection |
| #1092230 | FogBugz SSRF via `Kernel.open` | **Fixed** | No `Kernel.open`/`URI.open` in production; download service uses strict `*.fogbugz.com` domain allowlist |

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
21. **Multipart Uploads**: Workhorse JWT validation, `UploadedFile` path checks, `FileMover`
22. **Frontend Vue Components**: `v-html` usage in diffs, wikis, commit messages
23. **Dependency Proxy**: Docker registry URL handling, SSRF filtering
24. **Package Registry**: NuGet, Debian, npm package processing
25. **Object Storage**: Signed URL generation, path traversal in `remote_id` processing

---

## Recommendations

While no proven vulnerabilities were found, the following improvements would further harden the codebase (ordered by priority):

1. **Pre-extraction tar validation**: Validate tar archive contents (checking for symlinks, absolute paths) BEFORE extraction rather than cleaning up after, to eliminate the TOCTOU window in `lib/gitlab/import_export/command_line_util.rb:95-98`.

2. **Jenkins integration URL validator**: Change from `addressable_url: true` to `public_url: true` for consistency with other integrations, preventing SSRF to localhost/internal IPs at configuration time.

3. **HelpController defense-in-depth**: Add `File.realpath` + prefix check to `app/controllers/help_controller.rb:38-46` rather than relying solely on `clean_path_info` for path sanitization.

4. **CI remote include cache scoping**: When `ci_cache_remote_includes` feature flag is enabled, scope the cache key to the project namespace to prevent cross-project cache sharing.

5. **Add `exp` claim to multipart upload JWTs**: `lib/gitlab/middleware/multipart.rb` generates JWTs without expiration. Add a short TTL (e.g., 5 minutes) to limit replay window.

6. **Kramdown defense-in-depth**: Add explicit `forbidden_inline_options` configuration at the application level rather than relying solely on the upstream Kramdown gem version for CVE-2021-28834 protection.

7. **Explicit URL allowlists for SSRF-sensitive features**: Features like ActivityPub federation and CI remote includes could benefit from explicit domain allowlists rather than relying solely on IP-based blocking.

8. **Reduce `html_safe` surface area**: The codebase has many `html_safe` calls. While each individually appears safe, the pattern is error-prone for future development. Consider using Rails' `safe_join` and tag helpers more consistently.

9. **Convert tooling shell commands to array form**: `tooling/lib/tooling/predictive_tests/mapping_fetcher.rb:132` and `scripts/lint/validate_fast_spec_helper_usage.rb:55-57` use string interpolation in shell commands. While not production code, CI tooling with shell injection could be exploited via crafted file paths or branch names.

10. **Dependency proxy SSRF feature flag**: Ensure `dependency_proxy_for_containers_ssrf_protection` feature flag is enabled by default, as disabling it removes Workhorse-level SSRF filtering for Docker Hub downloads.

---

*Report generated by automated static analysis using 23 specialized workers. All findings are based on code review only. Runtime behavior may differ. "Needs Confirmation" items require dynamic testing.*
