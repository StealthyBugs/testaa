# DELIVERABLE A: GitLab Bug Pattern Playbook

## Consolidated from 22 Public HackerOne Reports

---

## 1. TOP 10 RECURRING VULNERABILITY PATTERNS

### Pattern 1: Command/Code Injection via Import Subsystem
**Reports:** #1609965, #1672388, #1679624, #1125425, #1154542
**Root Cause:** User-controlled data reaches process execution sinks without proper sanitization.
- String interpolation in shell commands: `Open3.popen3("gzip -dc #{@archive_path} | wc -c")` (#1609965)
- Sawyer::Resource objects with overridable `to_s`/`bytesize` poisoning Redis RESP protocol (#1672388, #1679624)
- Kramdown ERB template rendering via `other_markup_unsafe` on wiki content (#1125425)
- ExifTool `eval` on DjVu annotation content, reachable pre-auth (#1154542)
**Sinks:** `Open3.popen3` (string form), Redis command builder, `ERB.new().result`, ExifTool Perl `eval`
**Fix Pattern:** Use array form for process execution, validate/allowlist object types before cache operations, disable dangerous template defaults, sandbox file processors

### Pattern 2: Path Traversal / Arbitrary File Read via Import/Export
**Reports:** #827052, #1132378, #1439593, #733072
**Root Cause:** File paths derived from user input without canonicalization or traversal checks.
- UploadsRewriter regex `(?<file>.*?)` accepting `../../` sequences (#827052)
- JSON schema validator following `$ref` to local files (#1132378)
- Symlinks in tar archives not removed during bulk import extraction (#1439593)
- URL-encoded path traversal (`%2f`, `%2e`) bypassing validation in package registry (#733072)
**Sinks:** `File.read`, `find_file`, `open-uri`, tar extraction without symlink checks
**Fix Pattern:** Canonicalize paths, check against jail directory, remove symlinks from archives, decode before validating

### Pattern 3: Stored XSS via Banzai Markdown Pipeline
**Reports:** #2257080, #1731349, #1212067, #723307, #1578400
**Root Cause:** HTML constructed via string interpolation in Banzai filters, or unsanitized data reaching DOM.
- AbstractReferenceFilter mXSS via HTML4/5 parser differential (#2257080)
- Kroki filter: `"<img src=\"#{image_src}\" />"` string interpolation (#1731349)
- DesignReferenceFilter regex allowing HTML injection (#1212067)
- Branch names rendered as raw HTML in Vue components (#723307)
- Contact names unescaped in quick command dropdowns (#1578400)
**Sinks:** String interpolation in HTML, `v-html`, `.html_safe`, `raw()`, unescaped template variables
**Fix Pattern:** Use safe HTML builders (Nokogiri), escape all user data in HTML context, use `{{ }}` not `v-html`

### Pattern 4: SSRF via Import/Integration URL Fetching
**Reports:** #1092230, #1672388
**Root Cause:** External URL fetching that bypasses GitLab's SSRF protection layer (Gitlab::HTTP).
- FogBugz import using `CarrierWave::Uploader::Base#download!` → `Kernel.open` (#1092230)
- GitHub import fetching from attacker-controlled server (#1672388)
**Sinks:** `Kernel.open`, `open-uri`, `CarrierWave#download!`, direct `Net::HTTP` without UrlBlocker
**Fix Pattern:** Route ALL external HTTP through `Gitlab::HTTP` (which includes UrlBlocker), never use `Kernel.open`

### Pattern 5: Git Flag/Argument Injection
**Reports:** #658013, #653125
**Root Cause:** User-supplied ref/branch names passed to git CLI without `--` separator or `-` prefix validation.
- Search API `ref` param → `git log --output=/tmp/file` (#658013)
- Commits API `ref_name` → `git log` / `git rev-list` flag injection (#653125)
**Sinks:** Git CLI commands constructed without `--` argument terminator
**Fix Pattern:** Always use `--` before positional args in git commands, reject refs starting with `-`

### Pattern 6: Mass Assignment / IDOR in Project Import
**Reports:** #743953, #767770
**Root Cause:** Import JSON attributes assigned to models without allowlisting, enabling foreign key manipulation.
- `project_tree_restorer.rb`: `@project.assign_attributes(project_params)` accepting `issue_ids`, `merge_request_ids` (#743953)
- Bypass via nested `attributes` object (#767770 - incomplete fix of #743953)
**Sinks:** ActiveRecord mass assignment from import payloads
**Fix Pattern:** Strict allowlist of importable attributes, recursively filter nested attribute objects

### Pattern 7: XSS via Imported Data (Cross-System Trust Boundary)
**Reports:** #1665658, #1578400
**Root Cause:** Data imported from external systems (GitHub, CRM) trusted without output encoding.
- GitHub label colors stored and rendered without hex validation (#1665658)
- Customer contact names rendered in quick command UI without escaping (#1578400)
**Sinks:** DOM insertion of externally-sourced data, style attribute injection
**Fix Pattern:** Validate format (e.g., hex color regex), always encode on output regardless of source

### Pattern 8: Authentication Bypass / Privilege Escalation
**Reports:** #493324, #2293343
**Root Cause:** Logic flaws in authentication/session workflows.
- Admin impersonation session not isolated from target user (#493324)
- Password reset accepting JSON array of emails, sending reset link to attacker's email too (#2293343)
**Sinks:** Session management, password reset token delivery
**Fix Pattern:** Enforce type checking on parameters, isolate privilege contexts, validate token delivery targets

### Pattern 9: Unsafe Third-Party Tool Integration
**Reports:** #1154542, #1125425
**Root Cause:** Third-party tools (ExifTool, Kramdown) invoked with dangerous default configurations on untrusted input.
- ExifTool ignores file extensions, parses by content → DjVu eval RCE (#1154542)
- Kramdown processes `template` option by default → ERB execution (#1125425)
**Sinks:** ExifTool DjVu parser `eval`, Kramdown ERB template processing
**Fix Pattern:** Disable dangerous defaults, sandbox tool execution, don't trust extension-based filtering

### Pattern 10: Incomplete Fix / Filter Bypass
**Reports:** #767770, #1679624, #658013→#682442
**Root Cause:** Security fixes that are too narrow, addressing one path but missing structurally identical alternatives.
- #743953 fix blocked top-level `_ids` but not nested `attributes` (#767770)
- #1672388 fix patched one Redis path but missed repository cache adapter (#1679624)
- #658013 fixed `wiki_blobs` scope but `blobs` scope had same vuln (#682442)
**Lesson:** Fixes must address the root cause (centralized validation), not just the specific reported path.

---

## 2. "RED FLAG" FUNCTIONS AND MODULES

### Ruby/Rails Red Flags
| Function/Pattern | Risk | Context |
|---|---|---|
| `Open3.popen3(string)` | Command injection | String form instead of array form |
| `system(string)` | Command injection | String form instead of array form |
| `` `command #{var}` `` | Command injection | Backtick with interpolation |
| `Kernel.open` / `URI.open` | SSRF | Follows redirects, no IP blocking |
| `CarrierWave#download!` | SSRF | Uses open-uri internally |
| `Marshal.load` | Deserialization RCE | On any untrusted data |
| `YAML.load` (not safe_load) | Deserialization RCE | Permits arbitrary objects |
| `ERB.new(user_data).result` | Template injection | Direct code execution |
| `.html_safe` / `raw()` | XSS | On user-controlled data |
| `send(user_input)` | Arbitrary method call | Method name from user |
| `constantize` | Code injection | Class name from user |
| `assign_attributes(hash)` | Mass assignment | Without allowlist |
| `File.read(user_path)` | LFI | Without path validation |
| `gsub` building HTML | XSS | String-based HTML construction |

### GitLab-Specific Red Flag Modules
| Module/Area | Historical Risk | Reports |
|---|---|---|
| `lib/gitlab/import_export/` | Command injection, file read, mass assignment | #1609965, #827052, #1132378, #743953, #767770 |
| `lib/gitlab/github_import/` | RCE via Sawyer::Resource | #1672388, #1679624 |
| `lib/bulk_imports/` | File read via symlinks, command injection | #1439593, #1609965 |
| `lib/banzai/filter/` | Stored XSS | #2257080, #1731349, #1212067 |
| `app/uploaders/` | Path traversal | #827052 |
| Workhorse file handling | Pre-auth code execution | #1154542 |
| Package registry API | Path traversal | #733072 |
| Search API (ref params) | Git flag injection | #658013, #653125 |

---

## 3. STATIC ANALYSIS CHECKLIST BY VULNERABILITY CLASS

### Command/Code Injection Checklist
- [ ] All `Open3.*`, `system`, backticks, `IO.popen`, `Process.spawn` - verify array form
- [ ] All interpolation into shell command strings
- [ ] All `eval`, `instance_eval`, `class_eval`, `module_eval` with any user-influenced data
- [ ] `ERB.new` with user-controlled templates
- [ ] `send`/`public_send` with user-controlled method names
- [ ] `constantize` / `const_get` with user-controlled class names
- [ ] Git command construction without `--` separator

### SSRF Checklist
- [ ] All HTTP client usage: verify goes through `Gitlab::HTTP` / `Gitlab::HTTP_V2`
- [ ] `Kernel.open`, `URI.open`, `open-uri` - should never be used for URLs
- [ ] `CarrierWave#download!` - must use safe downloader
- [ ] Webhook URL validation before delivery
- [ ] Integration/service URL validation
- [ ] DNS rebinding protection completeness (check TTL handling)
- [ ] IPv6 address handling in URL blockers
- [ ] Redirect following through the protection layer

### Path Traversal / File Read Checklist
- [ ] All `File.read`, `File.open`, `IO.read` with constructed paths
- [ ] `send_file` / `send_data` with user-influenced paths
- [ ] Archive extraction: symlink handling, path canonicalization
- [ ] URL-encoded paths decoded BEFORE validation (not after)
- [ ] Upload path construction from user-supplied filenames
- [ ] JSON schema `$ref` resolution restricted to safe URIs
- [ ] `File.join` with user input - check for `../` after join

### XSS Checklist
- [ ] Banzai filters: string interpolation in HTML output
- [ ] `.html_safe` on anything derived from user input
- [ ] `raw()` helper usage
- [ ] Vue `v-html` bindings
- [ ] Imported data rendered without encoding (labels, names, etc.)
- [ ] Filter ordering: post-sanitization HTML generation
- [ ] Content-Type headers for user-uploaded files

### Mass Assignment / IDOR Checklist
- [ ] Import attribute handling: allowlist vs blocklist
- [ ] Nested attribute objects in import payloads
- [ ] `find_by(id: params[:id])` without user-scoped queries
- [ ] Foreign key assignment during import
- [ ] GraphQL resolver authorization checks

---

## 4. PRIORITIZED SUBSYSTEM MAP

**Tier 1 - Highest Historical Risk (multiple critical bugs):**
1. Import/Export pipeline (`lib/gitlab/import_export/`, `lib/bulk_imports/`)
2. GitHub/external service importers (`lib/gitlab/github_import/`)
3. Banzai markdown rendering (`lib/banzai/`)
4. Workhorse file upload processing

**Tier 2 - High Risk (critical bugs or systemic patterns):**
5. Package registry API (`lib/api/`, package models)
6. Git command construction (Gitaly interface, search API)
7. Webhook/integration HTTP clients
8. Authentication/session management

**Tier 3 - Elevated Risk (medium bugs or adjacent attack surface):**
9. GraphQL resolvers and mutations
10. CI/CD variable handling and config parsing
11. OAuth/OmniAuth callbacks
12. Admin impersonation features

---

## 5. CONCRETE EXAMPLES FROM REPORTS (Summarized)

### Example A: String Interpolation → RCE (#1609965)
```ruby
# VULNERABLE: archive_path from import_source param reaches shell
command = "gzip -dc #{@archive_path} | wc -c"
Open3.popen3(command) # string form = shell interpretation
# Payload: import_source = "/tmp/x;id>/tmp/pwned;#"
```

### Example B: Sawyer::Resource → Redis Protocol Injection → RCE (#1672388)
```ruby
# GitHub API response creates Sawyer::Resource with overridden to_s/bytesize
# Object reaches Redis via cache operations
# Bytesize mismatch corrupts RESP protocol → inject REPLICAOF → RCE
```

### Example C: Path Traversal via Upload Regex (#827052)
```ruby
# VULNERABLE regex: file group accepts ../
MARKDOWN_PATTERN = %r{\!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}
# Payload in issue description:
# ![a](/uploads/11111111111111111111111111111111/../../../../../../etc/passwd)
```

### Example D: Symlink File Read via Tar (#1439593)
```
# Attack: craft uploads.tar.gz containing:
# uploads/symlink_file -> /etc/passwd
# During bulk import, symlink is extracted and followed → file content served as upload
```

### Example E: mXSS via Parser Differential (#2257080)
```
# HTML4 parser sees: <a href="payload">
# HTML5 parser re-parses with / as attribute delimiter → attribute injection
# Result: XSS bypassing sanitize library
```

---

*Playbook produced from analysis of HackerOne reports: #2293343, #2257080, #1731349, #723307, #1665658, #1672388, #1578400, #1679624, #733072, #743953, #767770, #1609965, #1439593, #1212067, #1092230, #1132378, #1154542, #1125425, #493324, #827052, #658013, #653125*
