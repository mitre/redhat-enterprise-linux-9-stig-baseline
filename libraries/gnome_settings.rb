require "inspec/utils/filter"
require "hashie/mash"

# Create custom Mash subclass with warnings disabled for GNOME settings
class GnomeSettingsMash < Hashie::Mash
  disable_warnings
end

module Inspec::Resources
  class GnomeSettings < Inspec.resource(1)
    name "gnome_settings"
    supports platform: "linux"
    desc "Use the gnome_settings InSpec audit resource to test GNOME configuration settings"

    example <<~EXAMPLE
      # 1. Schema-scoped access (primary interface)
      describe gnome_settings('desktop.screensaver') do
        its('lock-enabled') { should cmp 'true' }
        its('lock_enabled') { should cmp 'true' }  # Underscore conversion works
        its('lock-delay') { should cmp <= 5 }
        its('picture-uri') { should cmp '' }  # Should be empty for security
      end

      describe gnome_settings('login-screen') do
        its('banner-message-enable') { should cmp 'true' }
        its('disable-user-list') { should cmp 'true' }
      end

      # 2. Global convenience methods (STIG shortcuts)
      describe gnome_settings do
        its('screensaver_lock_enabled') { should cmp 'true' }
        its('screensaver_lock_delay') { should cmp <= 5 }
        its('session_idle_delay') { should cmp <= 900 }
        its('login_banner_enabled') { should cmp 'true' }
        its('media_automount_open') { should cmp 'false' }
        its('media_autorun_never') { should cmp 'true' }
      end

      # 3. FilterTable queries (complex filtering)
      describe gnome_settings.where(schema: /desktop/) do
        it { should exist }
        its('count') { should be > 10 }
      end

      describe gnome_settings.where(type: 'boolean', value: true) do
        its('keys') { should include 'lock-enabled' }
      end

      describe gnome_settings.where(schema: 'desktop.screensaver') do
        its('values') { should include true }  # lock-enabled should be true
      end

      # 4. Structured data access (Hashie::Mash)
      describe gnome_settings do
        its('settings.desktop_screensaver.lock_enabled') { should cmp 'true' }
        its('parsed_data.desktop.screensaver.lock_enabled') { should cmp 'true' }
      end

      # 5. Schema and setting enumeration
      describe gnome_settings do
        its('available_schemas') { should include 'desktop.screensaver' }
        its('schema_settings("desktop.screensaver")') { should include 'lock-enabled' }
      end

      describe gnome_settings('desktop.screensaver') do
        its('available_settings') { should include 'lock-enabled' }
        its('available_settings.count') { should be > 10 }
      end

      # 6. Raw data access (debugging/advanced)
      describe gnome_settings do
        its('all_settings_hash.keys') { should include 'desktop.screensaver' }
        it { should have_setting('desktop.screensaver', 'lock-enabled') }
      end

      # STIG Control Examples
      # SV-258021: Screensaver lock must be enabled
      describe gnome_settings('desktop.screensaver') do
        its('lock_enabled') { should cmp 'true' }
      end

      # SV-258023: Session idle delay
      describe gnome_settings('desktop.session') do
        its('idle_delay') { should cmp <= input('graphical_user_session_inactivity_timeout') }
      end

      # SV-258012: Login banner must be enabled and contain required text
      describe gnome_settings('login-screen') do
        its('banner_message_enable') { should cmp 'true' }
      end

      # Exact banner text validation (legal compliance - must match exactly)
      describe gnome_settings do
        # RSpec expect style
        it 'should have exact banner text match' do
          expect(subject.content_matches?(input('banner_message_text_cli'))).to eq(true)
        end

        # InSpec matcher style
        it { should have_content_matching(input('banner_message_text_cli')) }

        # Direct comparison style
        its('banner_text_normalized') { should cmp input('banner_message_text_cli').gsub(/[\r\n\s]/, '') }
      end

      # Natural language boolean matchers (RSpec automatic predicates)
      describe gnome_settings do
        it { should have_exact_content(input('banner_message_text_cli')) }
        it { should have_banner_configured }
        it { should have_delay(input('screensaver_lock_delay')) }
        it { should have_timeout(input('graphical_user_session_inactivity_timeout')) }
        it { should have_setting_enabled('desktop.screensaver', 'lock-enabled') }
      end

      # Type-specific validation helpers
      describe gnome_settings do
        it { should have_setting_within_range('desktop.screensaver', 'lock-delay', 0, 10) }
        it { should have_setting_empty('desktop.screensaver', 'picture-uri') }
        it { should have_setting_containing('login-screen', 'banner-message-text', 'Government') }
      end

      # Schema metadata access
      describe gnome_settings do
        its('setting_type("desktop.screensaver", "lock-delay")') { should eq 'integer' }
        its('setting_raw_value("login-screen", "banner-message-enable")') { should match /false|true/ }
      end

      # Security-focused groupings
      describe gnome_settings do
        its('lockdown_settings.count') { should be > 0 }
        its('privacy_settings.count') { should be > 0 }
        its('session_security_settings.count') { should be > 10 }
        its('security_relevant_settings.count') { should be > 20 }
      end

      # Alternative: Check for presence of banner without exact text match
      describe gnome_settings('login-screen') do
        its('banner_message_text') { should_not be_empty }
        its('banner_message_text.length') { should be > 100 }
      end
    EXAMPLE

    attr_reader :schema_filter, :settings_cache, :settings_mash, :parsed_data

    def initialize(schema_filter = nil)
      @schema_filter = clean_schema_name(schema_filter) if schema_filter
      @settings_cache = nil
      @settings_mash = nil
      @parsed_data = nil

      # Check if gsettings is available
      unless gsettings_available?
        return skip_resource "gsettings not available - GNOME desktop environment not detected"
      end

      super()
    end

    # FilterTable setup
    filter_table = FilterTable.create
    filter_table.register_column(:schemas, field: :schema)
               .register_column(:keys, field: :key)
               .register_column(:values, field: :value)
               .register_column(:raw_values, field: :raw_value)
               .register_column(:types, field: :type)
               .register_column(:full_keys, field: :full_key)
               .register_custom_matcher(:has_schema?) { |table, schema|
                 clean_name = schema.to_s.sub(/^org\.gnome\./, '')
                 table.schemas.include?(clean_name)
               }
               .install_filter_methods_on_resource(self, :fetch_settings_data)

    # Schema-scoped bracket access (primary interface)
    def [](key)
      return nil unless @schema_filter

      setting = fetch_settings_data.find { |s| s[:schema] == @schema_filter && s[:key] == key }
      setting ? setting[:value] : nil
    end

    # Convenience methods for common settings (parameterized schema names)
    def screensaver_lock_enabled(schema = 'desktop.screensaver')
      get_setting_value(schema, 'lock-enabled')
    end

    def screensaver_lock_delay(schema = 'desktop.screensaver')
      get_setting_value(schema, 'lock-delay')
    end

    def session_idle_delay(schema = 'desktop.session')
      get_setting_value(schema, 'idle-delay')
    end

    def login_banner_enabled(schema = 'login-screen')
      get_setting_value(schema, 'banner-message-enable')
    end

    def login_banner_text(schema = 'login-screen')
      get_setting_value(schema, 'banner-message-text')
    end

    def media_automount_open(schema = 'desktop.media-handling')
      get_setting_value(schema, 'automount-open')
    end

    def media_autorun_never(schema = 'desktop.media-handling')
      get_setting_value(schema, 'autorun-never')
    end

    # Content matching for exact compliance validation (legal requirement)
    def content_matches?(expected_text)
      current_text = login_banner_text
      return false unless current_text

      # Exact character-by-character match after whitespace normalization (following SV-257779 pattern)
      normalize_banner_text(current_text) == normalize_banner_text(expected_text)
    end

    def banner_text_normalized
      normalize_banner_text(login_banner_text) if login_banner_text
    end

    # Alias for banner-specific use
    def banner_text_matches?(expected_text)
      content_matches?(expected_text)
    end

    # Boolean predicate methods for natural RSpec matchers (building blocks, not opinions)
    def has_exact_content?(expected_text)
      content_matches?(expected_text)
    end

    def has_banner_configured?(schema = 'login-screen')
      banner_enabled = get_setting_value(schema, 'banner-message-enable')
      banner_text = get_setting_value(schema, 'banner-message-text')
      banner_enabled && !banner_text.to_s.empty?
    end

    def has_delay?(max_delay, schema = 'desktop.screensaver', key = 'lock-delay')
      delay = get_setting_value(schema, key)
      delay && delay.to_i <= max_delay
    end

    def has_timeout?(max_timeout, schema = 'desktop.session', key = 'idle-delay')
      timeout = get_setting_value(schema, key)
      timeout && timeout.to_i <= max_timeout
    end

    def has_setting_enabled?(schema, key)
      value = get_setting_value(schema, key)
      value == true
    end

    def has_setting_disabled?(schema, key)
      value = get_setting_value(schema, key)
      value == false
    end

    def has_setting_locked?(schema, key)
      setting_locked?(schema, key)
    end

    # Type-specific helpers
    def has_setting_within_range?(schema, key, min, max)
      value = get_setting_value(schema, key)
      return false unless value.is_a?(Numeric)
      value >= min && value <= max
    end

    def has_setting_exceeding?(schema, key, threshold)
      value = get_setting_value(schema, key)
      return false unless value.is_a?(Numeric)
      value > threshold
    end

    def has_setting_empty?(schema, key)
      value = get_setting_value(schema, key)
      value.nil? || value.to_s.empty?
    end

    def has_setting_containing?(schema, key, substring)
      value = get_setting_value(schema, key)
      return false unless value.is_a?(String)
      value.include?(substring)
    end

    # Complex validation with Ruby best practices (options hash with fetch for RSpec compatibility)
    def has_valid_timeout?(schema, key, max_timeout, options = {})
      # Get current value with early return for type safety
      value = get_setting_value(schema, key)
      return false unless value.is_a?(Integer)

      # Use fetch for safe options access (Ruby best practice)
      require_locked = options.fetch(:require_locked, false)
      min_timeout = options.fetch(:min_timeout, 0)

      # Validate range using Ruby's between? method for clarity
      value_in_range = value.between?(min_timeout, max_timeout)

      # Short-circuit evaluation for performance
      return value_in_range unless require_locked

      # Only check lock if required (performance optimization)
      value_in_range && setting_locked?(schema, key)
    end

    def has_valid_delay?(schema, key, max_delay, options = {})
      has_valid_timeout?(schema, key, max_delay, options)
    end

    # Combined gsettings + dconf validation (addressing PR #93's dual checks)
    def has_enforced_setting?(schema, key, expected_value)
      # Check both runtime value AND administrative lock
      value_correct = get_setting_value(schema, key) == expected_value
      administratively_locked = setting_locked?(schema, key)

      value_correct && administratively_locked
    end

    # Check if setting is administratively locked via dconf
    def setting_locked?(schema, key)
      dconf_setting_locked?(schema, key)
    end

    # Schema metadata helpers
    def setting_type(schema, key)
      setting = fetch_settings_data.find { |s| s[:schema] == clean_schema_name(schema) && s[:key] == key }
      setting ? setting[:type] : nil
    end

    def setting_raw_value(schema, key)
      setting = fetch_settings_data.find { |s| s[:schema] == clean_schema_name(schema) && s[:key] == key }
      setting ? setting[:raw_value] : nil
    end

    # Security-focused groupings
    def lockdown_settings
      lockdown_schema = clean_schema_name('desktop.lockdown')
      fetch_settings_data.select { |s| s[:schema] == lockdown_schema }
    end

    def privacy_settings
      privacy_schema = clean_schema_name('desktop.privacy')
      fetch_settings_data.select { |s| s[:schema] == privacy_schema }
    end

    def session_security_settings
      relevant_schemas = ['desktop.session', 'desktop.screensaver', 'login-screen']
      fetch_settings_data.select { |s| relevant_schemas.include?(s[:schema]) }
    end

    # Bulk assessment helpers
    def non_default_settings
      # Note: Would need schema default values to implement fully
      # For now, return all settings (could be enhanced with schema parsing)
      fetch_settings_data
    end

    def security_relevant_settings
      security_patterns = ['lock', 'banner', 'timeout', 'delay', 'disable', 'enable', 'automount', 'autorun']
      fetch_settings_data.select do |setting|
        security_patterns.any? { |pattern| setting[:key].include?(pattern) || setting[:schema].include?(pattern) }
      end
    end

    # Schema enumeration
    def available_schemas
      fetch_settings_data.map { |s| s[:schema] }.uniq.sort
    end

    # Setting enumeration within current schema (if filtered)
    def available_settings
      return [] unless @schema_filter
      fetch_settings_data.select { |s| s[:schema] == @schema_filter }.map { |s| s[:key] }.sort
    end

    # Get all settings for a specific schema (even when not filtered)
    def schema_settings(schema_name)
      clean_schema = clean_schema_name(schema_name)
      fetch_settings_data.select { |s| s[:schema] == clean_schema }.map { |s| s[:key] }.sort
    end

    # Hashie::Mash interface (Ruby best practice: memoization with ||=)
    def settings
      @settings_mash ||= create_settings_mash
    end

    # Parsed data as nested hash (Ruby best practice: consistent memoization)
    def parsed_data
      @parsed_data ||= parse_recursive_data
    end

    # Helper method to get all GNOME settings as structured data
    def all_settings_hash
      hash = {}

      fetch_settings_data.each do |setting|
        schema = setting[:schema]
        key = setting[:key]

        hash[schema] ||= {}
        hash[schema][key] = setting[:value]
      end

      hash
    end

    # Check if a setting exists (Ruby best practice: guard clauses and early returns)
    def has_setting?(schema_or_key, key = nil)
      # Guard clause: handle single parameter case
      if key.nil?
        return false unless @schema_filter
        return fetch_settings_data.any? { |s| s[:schema] == @schema_filter && s[:key] == schema_or_key }
      end

      # Two parameter case: specific schema.key
      clean_schema = clean_schema_name(schema_or_key)
      return false unless clean_schema

      fetch_settings_data.any? { |s| s[:schema] == clean_schema && s[:key] == key }
    end

    # Dynamic method access for kebab-case settings (Ruby best practice implementation)
    def method_missing(method_name, *args, &block)
      # Guard clause: only handle when we have a schema filter
      return super unless @schema_filter

      # Reject if method has arguments (we only handle property access)
      return super unless args.empty? && block.nil?

      # Convert method name to kebab-case setting name
      setting_key = method_name.to_s.gsub('_', '-')

      # Performance optimization: cache the check to avoid repeated lookups
      if has_setting?(setting_key)
        self[setting_key]
      else
        super
      end
    end

    def respond_to_missing?(method_name, include_private = false)
      return super unless @schema_filter
      return false unless method_name.is_a?(Symbol) || method_name.is_a?(String)

      setting_key = method_name.to_s.gsub('_', '-')
      has_setting?(setting_key) || super
    end

    def to_s
      @schema_filter ? "GNOME Settings[#{@schema_filter}]" : "GNOME Settings"
    end

    def resource_id
      @schema_filter || "gnome_settings"
    end

    private

    def fetch_settings_data
      return @settings_cache if @settings_cache

      @settings_cache = []

      # Use gsettings list-recursively for efficient bulk data retrieval
      cmd = inspec.command('gsettings list-recursively')
      return @settings_cache if cmd.exit_status != 0

      cmd.stdout.each_line do |line|
        line.strip!
        next if line.empty?

        # Parse format: "org.gnome.desktop.screensaver lock-enabled true"
        parts = line.split(' ', 3)
        next unless parts.length >= 3

        full_schema = parts[0]
        key = parts[1]
        raw_value = parts[2]

        # Skip non-GNOME schemas
        next unless full_schema.start_with?('org.gnome.')

        # Clean schema name (remove org.gnome. prefix)
        clean_schema = clean_schema_name(full_schema)

        # Apply schema filter if specified
        next if @schema_filter && clean_schema != @schema_filter

        # Parse the value
        parsed_value = parse_gvariant_value(raw_value)

        @settings_cache << {
          schema: clean_schema,
          key: key,
          full_key: "#{clean_schema}.#{key}",
          value: parsed_value,
          raw_value: raw_value,
          type: determine_type(parsed_value),
          full_schema: full_schema
        }
      end

      @settings_cache
    end

    def get_setting_value(schema, key)
      clean_schema = clean_schema_name(schema)
      setting = fetch_settings_data.find { |s| s[:schema] == clean_schema && s[:key] == key }
      setting ? setting[:value] : nil
    end

    def clean_schema_name(schema_name)
      return nil unless schema_name

      # Remove org.gnome. prefix if present
      schema_name.to_s.sub(/^org\.gnome\./, '')
    end

    def parse_gvariant_value(value)
      case value
      when /^'([^']*)'$/  # String: 'value'
        $1
      when /^true$|^false$/  # Boolean
        value == 'true'
      when /^uint32 (\d+)$/  # uint32 integer - preserve type info
        $1.to_i
      when /^int32 (-?\d+)$/  # int32 integer
        $1.to_i
      when /^uint64 (\d+)$/  # uint64 integer
        $1.to_i
      when /^double (\d+\.?\d*)$/  # double float
        $1.to_f
      when /^\d+$/  # Plain integer
        value.to_i
      when /^\d+\.\d+$/  # Plain float
        value.to_f
      when /^\[.*\]$/  # Array
        begin
          JSON.parse(value.gsub("'", '"'))
        rescue
          value
        end
      else
        value
      end
    rescue
      value
    end

    def determine_type(value)
      case value
      when true, false then 'boolean'
      when Integer then 'integer'
      when Float then 'float'
      when Array then 'array'
      when String then 'string'
      else 'unknown'
      end
    end

    def gsettings_available?
      cmd = inspec.command('which gsettings')
      cmd.exit_status == 0
    end

    # Integration with dconf resource for lock checking (proper Ruby/InSpec way)
    def dconf_setting_locked?(schema, key)
      # Delegate to dconf resource instead of manual file parsing
      dconf_resource = Dconf.new(schema)
      dconf_resource.has_locked?(key)
    rescue
      false  # Graceful fallback if dconf not available
    end

    # Normalize banner text for exact character comparison (improved approach)
    def normalize_banner_text(text)
      return '' unless text

      text.to_s
          .gsub(/\\n|\\r/, "\n")       # Convert escaped newlines to actual newlines
          .gsub(/\r\n|\r/, "\n")       # Normalize line endings
          .gsub(/\n+/, "\n")           # Collapse multiple newlines
          .gsub(/[ \t]+/, ' ')         # Normalize spaces and tabs to single space
          .gsub(/\n /, "\n")           # Remove spaces after newlines
          .gsub(/ \n/, "\n")           # Remove spaces before newlines
          .strip                       # Remove leading/trailing whitespace
    end

    def create_settings_mash
      hash = {}

      fetch_settings_data.each do |setting|
        schema_key = setting[:schema].gsub('.', '_').gsub('-', '_')
        key = setting[:key].gsub('-', '_')

        hash[schema_key] ||= {}
        hash[schema_key][key] = setting[:value]  # Just store the value directly
      end

      GnomeSettingsMash.new(hash)
    end

    def parse_recursive_data
      # Parse the full gsettings recursive output into a clean nested structure
      hash = {}

      fetch_settings_data.each do |setting|
        schema_parts = setting[:schema].split('.')
        key = setting[:key].gsub('-', '_')  # Convert kebab-case to snake_case

        # Build nested hash structure
        current_level = hash
        schema_parts.each do |part|
          part_key = part.gsub('-', '_')
          current_level[part_key] ||= {}
          current_level = current_level[part_key]
        end

        # Set the final value
        current_level[key] = setting[:value]
      end

      GnomeSettingsMash.new(hash)
    end
  end
end

# Custom matcher for banner content validation
RSpec::Matchers.define :have_content_matching do |expected_text|
  match do |gnome_settings|
    gnome_settings.content_matches?(expected_text)
  end

  failure_message do |gnome_settings|
    current = gnome_settings.banner_text_normalized
    expected = gnome_settings.send(:normalize_banner_text, expected_text)
    "expected banner text to match exactly.\nExpected: #{expected}\nActual: #{current}"
  end

  description do
    "have banner content matching the specified text exactly"
  end
end