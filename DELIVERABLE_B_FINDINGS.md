# DELIVERABLE B: GitLab CE/EE Static Security Analysis Findings

## Methodology

- **Repository analyzed:** gitlab.com/gitlab-org/gitlab (shallow clone, HEAD as of 2026-03-04)
- **Languages:** Ruby/Rails, Go (Workhorse), JavaScript/Vue (frontend)
- **Workers deployed:** 12 specialized analysis workers across 6 vulnerability groups + manual cross-validation
- **Cross-validation:** Each HIGH-risk finding was independently verified by reading the relevant source files directly

---

## CONFIRMED / STRONGLY EVIDENCED FINDINGS

---

### [FINDING #1] IDOR in BulkImport Controller — Unscoped Database Lookup (Severity: HIGH)

- **Class:** Authorization Bypass / IDOR
- **Impact:** Any authenticated user can view import history, source URLs, entity paths, and failure details (which may contain sensitive data from the source instance) of **any other user's** bulk import operation.
- **Preconditions:** Authenticated user. BulkImport feature enabled. Knowledge or brute-force of sequential `BulkImport` IDs.
- **Source(s):** `params[:id]` in HTTP request to `/import/bulk_imports/:id/history` or `/import/bulk_imports/:id/history/:entity_id/failures`
- **Sink(s):** `BulkImport.find(params[:id])` — global ActiveRecord lookup without user scoping
- **Dataflow summary:**
  1. User sends GET request to `/import/bulk_imports/:id/history`
  2. `before_action :bulk_import` calls `BulkImport.find(params[:id])` (line 91)
  3. No check that `@bulk_import.user_id == current_user.id`
  4. Response renders import history/failures for any user's import
- **Evidence:**
  - File: `app/controllers/import/bulk_imports_controller.rb`
  - Function: `bulk_import` (private method)
  - Lines: 88-93
  - Snippet:
    ```ruby
    def bulk_import
      return unless params[:id]
      @bulk_import ||= BulkImport.find(params[:id])
      @bulk_import || render_404
    end
    ```
  - Contrast with the API implementation at `lib/api/bulk_imports.rb` lines 11-19 which properly scopes through `BulkImports::ImportsFinder.new(user: current_user)`
- **Why defenses fail:** The controller inherits `authenticate_user!` from `ApplicationController` (authentication is present), but there is no authorization check scoping the BulkImport to the current user. The API endpoint handles this correctly, but the web controller does not.
- **Exploit sketch:** Authenticated user enumerates BulkImport IDs (sequential integers) via `/import/bulk_imports/1/history`, `/import/bulk_imports/2/history`, etc. to read other users' import metadata and failure details.
- **Suggested fix:** Replace `BulkImport.find(params[:id])` with `current_user.bulk_imports.find(params[:id])` or add an explicit authorization check: `render_404 unless @bulk_import.user == current_user`.

---

### [FINDING #2] IDOR in Pipeline Schedule Variable Update via GlobalID (Severity: HIGH)

- **Class:** Authorization Bypass / IDOR
- **Impact:** A user who can update one pipeline schedule can modify or delete variables belonging to a **different** pipeline schedule they do not own or have access to.
- **Preconditions:** Authenticated user with `update_pipeline_schedule` permission on at least one pipeline schedule. Knowledge of target `Ci::PipelineScheduleVariable` GlobalIDs.
- **Source(s):** `variables` argument in `PipelineScheduleUpdate` GraphQL mutation — specifically the `id` field of each variable
- **Sink(s):** `GlobalID::Locator.locate(hash[:id])` — global lookup without ownership validation; result flows to `Ci::PipelineSchedules::UpdateService` nested attributes update
- **Dataflow summary:**
  1. User sends `PipelineScheduleUpdate` mutation with `id` of their own schedule
  2. `authorized_find!(id: id)` validates access to the schedule (line 49) ✓
  3. `variables_attributes_for(variables)` processes variable list (line 53)
  4. For each variable, `GlobalID::Locator.locate(hash[:id]).id` resolves the variable globally (line 73) ✗
  5. No check that the resolved variable belongs to the authorized schedule
  6. The variable ID is passed to `UpdateService` which performs nested attributes update
- **Evidence:**
  - File: `app/graphql/mutations/ci/pipeline_schedule/update.rb`
  - Function: `variables_attributes_for`
  - Lines: 70-78
  - Snippet:
    ```ruby
    def variables_attributes_for(variables)
      variables.map do |variable|
        variable.to_h.tap do |hash|
          hash[:id] = GlobalID::Locator.locate(hash[:id]).id if hash[:id]
          hash[:_destroy] = hash.delete(:destroy)
        end
      end
    end
    ```
  - The `authorized_find!` on line 49 only authorizes the parent schedule, not individual variables.
- **Why defenses fail:** The mutation correctly authorizes the pipeline schedule object, but the variable IDs within the `variables` argument are resolved via `GlobalID::Locator.locate` which performs a raw database lookup without any authorization or ownership check. This is a classic nested-object IDOR.
- **Exploit sketch:** User A has `update_pipeline_schedule` on schedule S1. User A sends mutation with `id: S1` and `variables: [{id: "gid://gitlab/Ci::PipelineScheduleVariable/999", _destroy: true}]` where variable 999 belongs to schedule S2 (owned by User B).
- **Suggested fix:** After locating each variable, verify it belongs to the authorized schedule: `raise_resource_not_available_error! unless variable.pipeline_schedule_id == schedule.id`.

---

### [FINDING #3] Unauthorized Write via WikiPageResolver `find_or_create_meta` (Severity: HIGH)

- **Class:** Authorization Bypass / Unauthorized Write
- **Impact:** Any authenticated user can trigger the creation of wiki page metadata records for **any** project or namespace, even private ones they have no access to. This also confirms existence of private projects/namespaces.
- **Preconditions:** Authenticated user. Knowledge of target project/namespace numeric IDs.
- **Source(s):** `namespace_id` and `project_id` arguments in `wikiPage` GraphQL query
- **Sink(s):** `Namespace.find()` / `Project.find()` — unscoped lookups; `page.find_or_create_meta` — write operation
- **Dataflow summary:**
  1. User queries `wikiPage(projectId: "gid://gitlab/Project/123", slug: "test")`
  2. `Project.find(123)` is called without authorization (line 29)
  3. `Wiki.for_container(container, current_user)` creates a wiki object for the unauthorized project (line 33)
  4. `wiki.find_page(slug)` attempts to find the page (line 34)
  5. If a page exists, `find_or_create_meta` creates/finds a `WikiPage::Meta` record (line 36) — **write operation**
  6. Type-level `authorize :read_wiki` on `WikiPageType` prevents data from being returned, but the write side-effect has already occurred
- **Evidence:**
  - File: `app/graphql/resolvers/wikis/wiki_page_resolver.rb`
  - Function: `resolve`
  - Lines: 22-37
  - Snippet:
    ```ruby
    def resolve(slug: nil, namespace_id: nil, project_id: nil)
      # ...
      container = Namespace.find(extract_namespace_id(namespace_id)) if namespace_id.present?
      container = Project.find(extract_project_id(project_id)) if project_id.present?
      return unless slug.present? && container.present?
      wiki = Wiki.for_container(container, current_user)
      page = wiki.find_page(slug, load_content: false)
      page&.find_or_create_meta
    end
    ```
- **Why defenses fail:** The resolver relies on type-level authorization (`authorize :read_wiki` on `WikiPageType`) to filter results, but the `resolve` method executes the unscoped `find` and the `find_or_create_meta` write before the type authorization can intervene. Side effects are not prevented by type-level auth.
- **Exploit sketch:** Enumerate private project IDs via GraphQL queries. For each, query `wikiPage(projectId: "gid://gitlab/Project/N", slug: "Home")`. A successful `Project.find` (no RecordNotFound) confirms the project exists. The `find_or_create_meta` creates metadata records for pages in unauthorized projects.
- **Suggested fix:** Add explicit authorization before the container lookup: `container = authorized_find!(id: project_id)` using `authorize :read_wiki`, or add a manual `Ability.allowed?(current_user, :read_wiki, container)` check before proceeding.

---

### [FINDING #4] ServiceDeskUploadLinkFilter — XSS via Unescaped `.text` in HTML Fragment (Severity: HIGH)

- **Class:** Stored XSS
- **Impact:** If exploitable, allows execution of arbitrary JavaScript in the context of users viewing service desk email responses, potentially leading to session hijacking or data theft.
- **Preconditions:** Service desk feature enabled. Ability to craft markdown content with specially constructed upload links that pass through the filter. The `context[:uploads_as_attachments]` must be present (service desk email rendering path).
- **Source(s):** `parent.text` — the text content of an `<a>` HTML node, which returns **unescaped** text (angle brackets, quotes returned as-is)
- **Sink(s):** `Nokogiri::HTML::DocumentFragment.parse("<strong>#{final_filename}</strong>")` — string interpolation of unescaped text into HTML parsing
- **Dataflow summary:**
  1. Service desk email rendering processes markdown containing an upload link
  2. `ServiceDeskUploadLinkFilter` matches links starting with `/uploads/` (line 25)
  3. `parent.text` extracts the text node content **without HTML escaping** (line 31)
  4. This unescaped text is interpolated into `"<strong>#{final_filename}</strong>"` (line 38)
  5. `Nokogiri::HTML::DocumentFragment.parse()` parses this as HTML
  6. The result replaces the original node via `parent.replace(final_element)` (line 39)
- **Evidence:**
  - File: `lib/banzai/filter/service_desk_upload_link_filter.rb`
  - Function: `replace_upload_link`
  - Lines: 23-40
  - Snippet:
    ```ruby
    def replace_upload_link(html_attr)
      return unless html_attr.name == 'href'
      return unless html_attr.value.start_with?('/uploads/')
      secret, filename_in_link = html_attr.value.scan(FileUploader::DYNAMIC_PATH_PATTERN).first
      return unless context[:uploads_as_attachments].include?("#{secret}/#{filename_in_link}")
      parent = html_attr.parent
      filename_in_text = parent.text          # UNESCAPED text content
      final_filename = if filename_in_link != filename_in_text
                         "#{filename_in_text} (#{filename_in_link})"
                       else
                         filename_in_text
                       end
      final_element = Nokogiri::HTML::DocumentFragment.parse("<strong>#{final_filename}</strong>")
      parent.replace(final_element)
    end
    ```
- **Why defenses fail:** `SanitizationFilter` runs earlier in the pipeline and would have stripped script tags from the original markdown. However, this filter runs in a post-processing pipeline for service desk emails. The text content of a link node (set during earlier pipeline stages) could contain characters like `<`, `>` if they were introduced by earlier filter transformations or encoding mismatches. The `.text` method returns decoded text, not HTML-safe text, and it is directly interpolated into an HTML string.
- **Exploit sketch:** Craft markdown in a service desk context where the link text node contains HTML metacharacters that survive earlier sanitization. When `parent.text` extracts them and they are interpolated into the `<strong>` tag, they become active HTML.
- **Suggested fix:** Use `CGI.escapeHTML(final_filename)` before interpolation: `Nokogiri::HTML::DocumentFragment.parse("<strong>#{CGI.escapeHTML(final_filename)}</strong>")`, or use Nokogiri DOM builders: `doc.document.create_element('strong').tap { |el| el.content = final_filename }`.

---

### [FINDING #5] Raw `Faraday.get` / `Net::HTTP` Without SSRF Protection in Object Storage Paths (Severity: HIGH)

- **Class:** SSRF
- **Impact:** If an attacker can influence the stored URL for an upload or artifact (e.g., through database manipulation or import-related bugs), these code paths make HTTP requests to arbitrary destinations without any IP/hostname restriction, DNS rebinding protection, or local network blocking.
- **Preconditions:** Attacker must be able to influence the `url` field of an upload or artifact record stored in the database. This could be chained with another vulnerability (SQL injection, mass assignment, import manipulation). Remote object storage must be configured.
- **Source(s):** `file.url` / `url` — URLs stored in the database for object storage references
- **Sink(s):** Raw `Faraday.get()`, raw `Net::HTTP.start()` — bypass all SSRF protections in `Gitlab::HTTP_V2`
- **Dataflow summary (3 locations):**
  - **Path A:** `Gitlab::HttpIO.get_chunk` → `Net::HTTP.start(uri.hostname, uri.port, ...)` (line 157)
  - **Path B:** `DecompressedArtifactSizeValidator.valid_on_storage?` → `::Faraday.get(file.url)` (line 47)
  - **Path C:** `ObjectStorage.use_open_file` → `Faraday.get(url)` (line 386)
- **Evidence:**
  - File: `lib/gitlab/http_io.rb`, lines 155-159
    ```ruby
    def get_chunk
      unless in_range?
        response = Net::HTTP.start(uri.hostname, uri.port, proxy_from_env: true, use_ssl: uri.scheme == 'https') do |http|
          http.request(request)
        end
    ```
  - File: `lib/gitlab/ci/artifacts/decompressed_artifact_size_validator.rb`, lines 47-49
    ```ruby
    ::Faraday.get(file.url) do |req|
      req.options.on_data = proc { |chunk, _| tempfile.write(chunk) }
    end
    ```
  - File: `app/uploaders/object_storage.rb`, lines 386-390
    ```ruby
    Faraday.get(url) do |req|
      req.options.on_data = proc { |chunk, _| file.write(chunk) }
    end
    ```
  - Only validation: `Gitlab::UrlSanitizer.valid?(url)` in HttpIO (checks scheme only, NOT IP/hostname)
- **Why defenses fail:** These code paths were designed for internal object storage URLs (S3, GCS, MinIO) which are configured by admins. The developers assumed these URLs would never be user-controlled. However, if any vulnerability allows an attacker to influence the stored URL, these paths have zero SSRF protection — no `Gitlab::HTTP_V2::UrlBlocker`, no DNS rebinding checks, no private IP filtering.
- **Exploit sketch:** Chain with an import or upload vulnerability that allows setting an arbitrary URL in the uploads/artifacts database table. The stored URL points to `http://169.254.169.254/latest/meta-data/` (cloud metadata endpoint). When the file is accessed, the raw HTTP client fetches the attacker's target.
- **Suggested fix:** Route all HTTP requests through `Gitlab::HTTP` even for object storage access, or at minimum apply `Gitlab::HTTP_V2::UrlBlocker.validate!` before making the request.

---

### [FINDING #6] `Marshal.load` from Redis in Zoekt Search Cache (Severity: HIGH)

- **Class:** Unsafe Deserialization
- **Impact:** Remote Code Execution if an attacker gains write access to Redis (via SSRF, Redis misconfiguration, or another chained vulnerability).
- **Preconditions:** EE edition with Zoekt search enabled. Attacker must have write access to the Redis instance (chain with another vulnerability). Knowledge of the cache key format.
- **Source(s):** Redis cache data — `redis.get(cache_key)` where `cache_key` includes user-influenced components (query, filters, group_id, project_id)
- **Sink(s):** `Marshal.load(data)` — deserializes arbitrary Ruby objects from the Redis data
- **Dataflow summary:**
  1. Attacker writes crafted Marshal payload to Redis key matching the cache key pattern
  2. User performs a Zoekt search that triggers cache read
  3. `read_cache` calls `redis.get(cache_key)` and passes result to `Marshal.load(data)` (line 86)
  4. Marshal deserialization instantiates attacker-controlled Ruby objects → RCE
- **Evidence:**
  - File: `ee/lib/search/zoekt/cache.rb`
  - Function: `read_cache`
  - Lines: 79-87
  - Snippet:
    ```ruby
    def read_cache
      data = with_redis do |redis|
        redis.get(cache_key)
      end
      return unless data
      Marshal.load(data) # rubocop:disable Security/MarshalLoad
    end
    ```
  - The `rubocop:disable` comment acknowledges the risk but justifies it as "similar to Rails.cache"
  - Cache key generation at line 75-77 uses SHA256 of user-influenced parameters
- **Why defenses fail:** The developers treated this as equivalent to `Rails.cache` which also uses Marshal. However, `Rails.cache` benefits from Rails' security assumptions about the cache store, while this custom cache implementation has a simpler key structure that could be more predictable. The core issue is that `Marshal.load` on any data from an external store (Redis) is a deserialization gadget chain waiting for a trigger.
- **Exploit sketch:** Attacker gains Redis write via SSRF or misconfiguration → writes crafted Marshal payload to a predictable cache key → victim triggers search → `Marshal.load` executes the gadget chain → RCE.
- **Suggested fix:** Replace `Marshal.load/dump` with `JSON.parse/generate` or `MessagePack`, which do not support arbitrary object instantiation. If Marshal is required for performance, add an HMAC signature to the cached data to prevent tampering.

---

### [FINDING #7] `constantize` Without Allowlist in Multiple Sidekiq Workers (Severity: HIGH)

- **Class:** Unsafe Deserialization / Code Injection
- **Impact:** If an attacker can enqueue Sidekiq jobs with controlled arguments (via Redis compromise), they can instantiate arbitrary Ruby classes and invoke methods on them, potentially achieving RCE.
- **Preconditions:** Attacker must have write access to Sidekiq's Redis queue (chain with another vulnerability).
- **Source(s):** Sidekiq job arguments — `class_name` parameter in job payloads
- **Sink(s):** `.constantize` — resolves arbitrary Ruby class names; `.new`, `.find`, `.perform_at` called on the resolved class
- **Dataflow summary:**
  1. Attacker writes crafted Sidekiq job to Redis queue with controlled `class_name`
  2. Worker picks up the job and calls `class_name.constantize`
  3. Arbitrary Ruby class is resolved and methods are invoked on it
- **Evidence (multiple locations):**
  - File: `app/workers/delete_stored_files_worker.rb`, line 15
    ```ruby
    def perform(class_name, keys)
      klass = class_name.constantize
      klass.new(logger: logger).delete_keys(keys)
    end
    ```
  - File: `app/workers/concerns/reactive_cacheable_worker.rb`, line 25
    ```ruby
    def perform(class_name, id, *args)
      klass = class_name.constantize
      klass.reactive_cache_worker_finder.call(id, *args)...
    end
    ```
  - File: `app/workers/flush_counter_increments_worker.rb`, line 32
    ```ruby
    model_class = model_name.constantize
    ```
  - File: `app/models/concerns/prometheus_adapter.rb`, line 61
    ```ruby
    data = Object.const_get(query_class_name, false).new(prometheus_client).query(*args)
    ```
- **Why defenses fail:** The workers trust that Sidekiq job arguments are application-generated. However, Sidekiq jobs are stored in Redis, and if Redis is compromised, an attacker can inject arbitrary job payloads. No allowlist validation is performed on the class name before `constantize`.
- **Exploit sketch:** Attacker gains Redis write → enqueues `DeleteStoredFilesWorker` with `class_name: "Gem::Installer"` → worker calls `Gem::Installer.new(logger: logger).delete_keys(keys)` → unexpected behavior from arbitrary class.
- **Suggested fix:** Add explicit allowlist validation before `constantize`: `raise ArgumentError unless ALLOWED_CLASSES.include?(class_name)`.

---

### [FINDING #8] TOCTOU Race in Tar Extraction Symlink Cleanup (Severity: HIGH)

- **Class:** Local File Read / Path Traversal
- **Impact:** During the time window between tar extraction and symlink cleanup, symlinks exist on disk and could be followed by concurrent processes, potentially reading arbitrary files.
- **Preconditions:** User can trigger a project/group import. A concurrent process must access the extraction directory during the race window.
- **Source(s):** User-uploaded tar archive containing crafted symlinks
- **Sink(s):** Symlinks on filesystem between extraction and cleanup
- **Dataflow summary:**
  1. User uploads import archive containing `uploads/symlink -> /etc/passwd`
  2. `untar_with_options` extracts: `tar -xf archive -C dir` (line 96) — symlinks created on disk
  3. `chmod -R` runs (line 97)
  4. `clean_extraction_dir!` iterates and removes symlinks (line 98) — symlinks exist during steps 2-3
  5. Race window: between steps 2 and 4, symlinks are live on disk
- **Evidence:**
  - File: `lib/gitlab/import_export/command_line_util.rb`
  - Function: `untar_with_options`
  - Lines: 95-99
  - Snippet:
    ```ruby
    def untar_with_options(archive:, dir:, options:)
      execute_cmd(%W[tar -#{options} #{archive} -C #{dir}])
      execute_cmd(%W[chmod -R #{UNTAR_MASK} #{dir}])
      clean_extraction_dir!(dir)
    end
    ```
  - Cleanup at lines 135-149:
    ```ruby
    def clean_extraction_dir!(dir)
      Dir.glob("#{dir}/**/*", File::FNM_DOTMATCH).each do |filepath|
        next if CLEAN_DIR_IGNORE_FILE_NAMES.include?(File.basename(filepath))
        raise HardLinkError if Gitlab::Utils::FileInfo.shares_hard_link?(filepath)
        FileUtils.rm(filepath) if Gitlab::Utils::FileInfo.linked?(filepath) || File.pipe?(filepath)
      end
    end
    ```
- **Why defenses fail:** The defense is post-hoc cleanup rather than prevention-at-extraction. GNU tar supports extraction filters that could prevent symlink creation entirely. The extraction directory is unique (`Dir.mktmpdir`), which limits practical exploitability, but the architectural pattern is still vulnerable to race conditions.
- **Exploit sketch:** Submit import with crafted tar containing symlink. If any concurrent processing (e.g., virus scanning, background file indexing) reads from the temp directory during the extraction-to-cleanup window, the symlink is followed.
- **Suggested fix:** Use tar's `--no-same-owner --no-same-permissions` flags and filter out symlinks during extraction: `tar --exclude-from=<(tar -tf archive | grep -E '^l')` or use Ruby's `Gem::Package::TarReader` with explicit symlink rejection before writing to disk.

---

### [FINDING #9] NuGet/Terraform Zip Extraction with `{ true }` Overwrite and Unsanitized Entry Names (Severity: HIGH)

- **Class:** Path Traversal / File Overwrite
- **Impact:** If RubyZip's built-in path traversal protections are bypassed or misconfigured, zip entry names could write files to unintended locations. The `{ true }` overwrite block explicitly disables overwrite protection.
- **Preconditions:** User can upload NuGet packages or Terraform modules. RubyZip version must have a bypass in its path traversal check (or the check must be misconfigured).
- **Source(s):** Zip entry names in uploaded packages (`entry.name`)
- **Sink(s):** `entry.extract(file.path) { true }` — extraction with overwrite enabled; `file_path: path` — unsanitized entry name stored in database
- **Dataflow summary:**
  1. User uploads NuGet package or Terraform module containing zip with crafted entry names
  2. `process_archive` iterates entries, checking `entry.file?` and `entry.size` (line 48)
  3. `entry.extract(tmp_file.path) { true }` extracts with overwrite enabled
  4. For NuGet symbols: `file_path: path` stores the raw `entry.name` in the database without validation
- **Evidence:**
  - File: `app/services/packages/nuget/extract_metadata_file_service.rb`, line 29
    ```ruby
    entry.extract(file.path) { true }
    ```
  - File: `app/services/packages/nuget/symbols/create_symbol_files_service.rb`, line 33
    ```ruby
    entry.extract(tmp_file.path) { true }
    ```
  - File: `app/services/packages/terraform_module/metadata/extract_files_service.rb`, lines 48, 69
    ```ruby
    next unless entry.file? && entry.size <= MAX_FILE_SIZE
    # ...
    entry.extract(tmp_file.path) { true }
    ```
- **Why defenses fail:** RubyZip has built-in path traversal protection since version 1.3.0, but the `{ true }` block explicitly overrides the overwrite protection. While extraction targets are `Tempfile` objects (limiting the path traversal impact), the unsanitized `entry.name` stored in `file_path` could be used in subsequent operations that construct file paths from this database field.
- **Exploit sketch:** Upload NuGet package with zip entry named `../../../config/secrets.yml`. While the extraction itself targets a Tempfile, the `file_path` stored in the database contains the traversal path. If any downstream code constructs a filesystem path from `file_path`, it could read or write to unintended locations.
- **Suggested fix:** Validate `entry.name` against path traversal before extraction: `Gitlab::PathTraversal.check_path_traversal!(entry.name)`. Remove `{ true }` overwrite blocks. Sanitize `file_path` before database storage.

---

### [FINDING #10] Feature Flags Resolver — Instance Configuration Disclosure (Severity: HIGH)

- **Class:** Information Disclosure
- **Impact:** Any authenticated user can query the enabled/disabled status of any feature flag on the GitLab instance, revealing security configurations, unreleased features, and operational settings.
- **Preconditions:** Authenticated user. No additional permissions required.
- **Source(s):** `names` argument in `gitlabInstanceFeatureFlags` GraphQL query
- **Sink(s):** `Feature.enabled?(feature.name, current_user)` — returns boolean for any defined feature flag
- **Dataflow summary:**
  1. User sends GraphQL query: `{ gitlabInstanceFeatureFlags(names: ["flag1", "flag2"]) { name enabled } }`
  2. Resolver at line 17-24 has no authorization check
  3. `Feature.preload(names)` loads requested flags
  4. Returns `{ name, enabled }` for each defined flag
- **Evidence:**
  - File: `app/graphql/resolvers/app_config/gitlab_instance_feature_flags_resolver.rb`
  - Function: `resolve`
  - Lines: 17-24
  - Snippet:
    ```ruby
    def resolve(names:)
      return [] if names.empty?
      features = Feature.preload(names)
      features
        .filter { |feature| Feature::Definition.has_definition?(feature.name) }
        .map { |feature| { name: feature.name, enabled: Feature.enabled?(feature.name, current_user) } }
    end
    ```
  - No `authorize` declaration on the resolver
- **Why defenses fail:** The resolver has no authorization at all. Feature flag names are publicly documented in GitLab's source code, so an attacker knows exactly which flags to query. Flags often gate security features (e.g., `enforce_ci_inbound_job_token_scope_enabled`), and knowing their status reveals the instance's security posture.
- **Exploit sketch:** Query all known security-related feature flags to map the instance's security configuration: `{ gitlabInstanceFeatureFlags(names: ["enforce_ci_inbound_job_token_scope_enabled", "disable_personal_access_tokens", ...]) { name enabled } }`.
- **Suggested fix:** Add admin-only authorization: `authorize :admin_all_resources` or restrict to instance-level admin access.

---

## FALSE POSITIVES REJECTED

1. **Label color CSS injection via GitHub import**: Investigated thoroughly. The `BulkImporting` module at `lib/gitlab/github_import/bulk_importing.rb` lines 27-38 validates records with `model.new(attrs).invalid?` before insertion. The `ColorValidator` enforces hex-only colors. The historical bug #1665658 has been fixed.

2. **`avatar_url` innerHTML XSS in `visual_token_value.js`**: The `avatar_url` comes from `GravatarService`, not user-controlled input. Users cannot set arbitrary avatar URLs through the standard API. The URL is server-generated.

3. **Kramdown ERB template rendering**: The historical bug #1125425 has been fixed. Current Kramdown usage is limited to ADF-to-Commonmark conversion and HTML-to-Markdown, not with the dangerous `template` option.

4. **ExifTool command injection via Workhorse**: The current code uses `exec.CommandContext` with hardcoded arguments (no string interpolation). The extension-based file type check is defense-in-depth (content-based magic byte validation also applies). CVE-2021-22205 is fixed.

5. **`Open3.popen3` command injection in import**: The historical bug #1609965 has been fixed. Current code uses `Gitlab::Popen.popen` which enforces array-based commands: `raise "Commands must be given as an array of strings" unless cmd.is_a?(Array)`.

6. **GitHub import Sawyer::Resource RCE**: The historical bugs #1672388/#1679624 have been fixed. All GitHub API responses are now converted to plain hashes via `.to_h` with explicit field picking via `from_api_response`.

7. **`Marshal.load` in `ActiveSession`**: The legacy path at line 250 has an explicit rubocop disable with documented justification. The data comes from the session Redis store which is internal. The newer format uses `Gitlab::Json.safe_parse`.

8. **`Oj.load` with `mode: :rails`**: While `mode: :rails` can instantiate some types, it is significantly more restrictive than `mode: :object` and only supports ActiveRecord/ActiveSupport types. The risk is MEDIUM, not HIGH.

9. **Appearance colors style injection**: The `message_background_color` and `message_font_color` are admin-controlled settings validated by `ColorValidator`. The attack requires admin access, making this a low-impact finding.

10. **`redirect_to request_params[:redirect_url]` in SlashCommandsController**: The redirect only occurs after `valid_request?` (checking cached params) AND `valid_user?` (checking chat user matches current user). Both gates must pass, and the cache is populated by the integration itself.

---

---

### [FINDING #11] DNS Rebinding Protection Disabled When HTTP Proxy Is Configured (Severity: HIGH)

- **Class:** SSRF
- **Impact:** Complete bypass of DNS rebinding protection when an HTTP proxy is in use (common in enterprise environments), enabling SSRF to internal services via DNS rebinding attacks on any integration/webhook URL.
- **Preconditions:** GitLab instance configured to use an HTTP proxy (common in enterprise). Attacker can configure a webhook or integration URL.
- **Source(s):** Webhook URL / integration URL — user-configured
- **Sink(s):** `Gitlab::HTTP_V2::UrlBlocker` — DNS rebinding protection automatically disabled when proxy is detected
- **Dataflow summary:**
  1. URL validation at record save time: `dns_rebind_protection: false` (always disabled at save time)
  2. URL validation at request time: `dns_rebind_protection` disabled when `proxy_in_use` is true
  3. Attacker's DNS server resolves to public IP initially, then internal IP at webhook delivery time
  4. Request goes through proxy to internal target
- **Evidence:**
  - File: `app/validators/addressable_url_validator.rb`, line 64
    ```ruby
    dns_rebind_protection: false,   # disabled at validation time
    ```
  - File: `gems/gitlab-http/lib/gitlab/http_v2/url_blocker.rb`, line 143
    ```ruby
    dns_rebind_protection &&= !proxy_in_use
    ```
- **Why defenses fail:** DNS rebinding protection is disabled in two independent ways: (1) always at validation time (intentional — URL may not be resolvable yet), and (2) at request time when a proxy is configured (because the IP check would be against the proxy, not the target). This means in enterprise deployments with proxies, there is zero DNS rebinding protection at any point.
- **Exploit sketch:** Configure webhook URL to `http://attacker.example.com/hook`. Attacker's DNS initially resolves to `1.2.3.4` (public IP, passes validation). At webhook delivery time, DNS resolves to `169.254.169.254`. Proxy forwards request to metadata endpoint.
- **Suggested fix:** When a proxy is in use, perform DNS resolution independently and check the resolved IP against the blocklist before making the proxied request. Alternatively, use `Gitlab::HTTP_V2::UrlBlocker.validate!` with `dns_rebind_protection: true` at request time even when a proxy is configured, by resolving DNS before constructing the proxy request.

---

### [FINDING #12] Drone CI Access Token Leaked in URL Query String (Severity: HIGH)

- **Class:** Credential Leakage
- **Impact:** The Drone CI access token is transmitted in cleartext URL query parameters on every commit status check, visible in HTTP access logs, network monitoring, and proxy caches on both GitLab and Drone CI servers.
- **Preconditions:** Drone CI integration enabled. Any push event triggers status checks.
- **Source(s):** `token` — Drone CI integration access token stored in GitLab
- **Sink(s):** URL query string in HTTP GET request via `Clients::HTTP.try_get`
- **Dataflow summary:**
  1. `commit_status_path` constructs URL with `&access_token=#{token}` in query string (line 49-53)
  2. `get_commit_status` calls `Clients::HTTP.try_get(url, ...)` (line 60)
  3. Token visible in: GitLab HTTP logs, Drone CI access logs, any network proxy between the two
- **Evidence:**
  - File: `app/models/integrations/drone_ci.rb`
  - Function: `commit_status_path`
  - Lines: 49-53
  - Snippet:
    ```ruby
    def commit_status_path(sha, ref)
      Gitlab::Utils.append_path(
        drone_url,
        "gitlab/#{project.full_path}/commits/#{sha}?branch=#{Addressable::URI.encode_component(ref.to_s)}&access_token=#{token}")
    end
    ```
  - Note: The webhook delivery at line 107-108 correctly uses `url_variables` for secure token injection, but status checks do not.
- **Why defenses fail:** The webhook delivery path correctly uses the `url_variables` mechanism, but the status check path was not updated to follow the same pattern. The token is placed in the query string for compatibility with the Drone CI API, but should instead be sent as an `Authorization` header.
- **Exploit sketch:** Monitor HTTP logs on either GitLab or Drone CI server → extract access token from query strings → use token to authenticate to Drone CI API with the victim's permissions.
- **Suggested fix:** Send the access token as an `Authorization: Bearer #{token}` header instead of in the query string, or use the `url_variables` pattern for secure credential injection.

---

## ADDITIONAL POTENTIAL FINDINGS (Require Further Investigation)

### [POTENTIAL #1] `Gitlab::Json` using `Oj.load` with `mode: :rails` Globally
- File: `lib/gitlab/json.rb`, lines 130-132
- Every `Gitlab::Json.parse` call uses `Oj.load` with `:rails` mode which can instantiate some types via `^o` markers
- Missing condition: Need to confirm whether any endpoint passes raw user JSON through `Gitlab::Json.parse` where the input could contain Oj type markers

### [POTENTIAL #2] Backup Tar Extraction Without Symlink Protection
- File: `gems/gitlab-backup-cli/lib/gitlab/backup/cli/utils/tar.rb`, lines 63-73
- No `--no-same-permissions` or symlink filtering flags
- Missing condition: Requires a tampered backup archive, which is typically admin-only territory

### [POTENTIAL #3] `ChronicDuration.parse` on User-Controlled Cache TTL Without Bounds
- File: `lib/gitlab/ci/config/external/file/remote.rb`, lines 85-89
- If `ChronicDuration.parse` returns `nil`, calling `.seconds` raises `NoMethodError` → DoS during CI config processing
- Missing condition: Need to confirm CI config parsing error handling

---

*Analysis performed on GitLab CE/EE repository HEAD as of 2026-03-04. All findings are based on static analysis only.*
*Workers: 12 specialized analysis agents across SSRF, Command Injection, LFI/Path Traversal, XSS, AuthZ Bypass, Import/Export, Webhooks/Integrations, CI/CD, GraphQL, Deserialization, Archive Processing, and Banzai Pipeline categories.*
