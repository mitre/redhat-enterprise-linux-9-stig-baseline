require "inspec/utils/filter"
require "hashie/mash"

# Create custom Mash subclass with warnings disabled for dconf data
class DconfDataMash < Hashie::Mash
  disable_warnings
end

module Inspec::Resources
  class Dconf < Inspec.resource(1)
    name "dconf"
    supports platform: "linux"
    desc "Use the dconf InSpec audit resource to test GNOME dconf policy configuration, locks, and database management"

    example <<~EXAMPLE
      # 1. Schema-scoped policy validation (primary interface)
      describe dconf('desktop.screensaver') do
        it { should have_setting('lock-enabled') }
        it { should have_locked('lock-enabled') }
        its('lock-enabled') { should cmp 'true' }
      end

      describe dconf('login-screen') do
        it { should have_setting('banner-message-enable') }
        it { should have_locked('banner-message-enable') }
      end

      # 2. Database management
      describe dconf do
        its('active_profile') { should eq 'user' }
        its('system_database') { should eq 'local' }
        its('available_databases') { should include 'local' }
        it { should have_databases_compiled }
      end

      # 3. Lock validation (security-critical)
      describe dconf do
        it { should have_setting_locked('desktop.media-handling', 'automount-open') }
        it { should have_setting_locked('login-screen', 'banner-message-enable') }
        its('locked_settings.count') { should be > 5 }
      end

      # 4. FilterTable queries (complex policy analysis)
      describe dconf.where(database: 'local') do
        it { should exist }
        its('count') { should be > 0 }
      end

      describe dconf.where(type: 'lock') do
        its('schemas') { should include 'desktop.screensaver' }
      end

      # 5. Natural language boolean matchers
      describe dconf do
        it { should have_policy_configured }
        it { should have_administrative_locks }
        it { should have_database_consistency }
        it { should have_setting_locked('desktop.screensaver', 'lock-enabled') }
      end

      # 6. Security-focused groupings
      describe dconf do
        its('security_locks.count') { should be > 10 }
        its('media_handling_locks.count') { should be > 0 }
        its('login_locks.count') { should be > 0 }
      end

      # STIG Control Examples
      # SV-258013: Banner message lock validation
      describe dconf('login-screen') do
        it { should have_locked('banner-message-enable') }
      end

      # SV-258015: Media automount lock validation
      describe dconf('desktop.media-handling') do
        it { should have_locked('automount-open') }
      end
    EXAMPLE

    attr_reader :schema_filter, :database_cache, :locks_cache, :settings_cache, :profile_cache, :dconf_db_path, :dconf_profile_path

    # Public access to data for debugging (instead of private methods)
    def settings_data
      fetch_dconf_data
    end

    def locks_data
      fetch_lock_data
    end

    def initialize(schema_filter = nil, dconf_db_path: '/etc/dconf/db', dconf_profile_path: '/etc/dconf/profile/user')
      @schema_filter = clean_schema_name(schema_filter) if schema_filter
      @database_cache = nil
      @locks_cache = nil
      @settings_cache = nil
      @profile_cache = nil

      # Configurable paths using keyword arguments (Ruby best practice)
      @dconf_db_path = dconf_db_path
      @dconf_profile_path = dconf_profile_path

      # Guard clause with early return (Ruby best practice)
      return skip_resource "dconf not available - GNOME desktop environment not detected" unless dconf_available?

      super()
    end

    # FilterTable setup for database entries
    filter_table = FilterTable.create
    filter_table.register_column(:databases, field: :database)
               .register_column(:paths, field: :path)
               .register_column(:keys, field: :key)
               .register_column(:values, field: :value)
               .register_column(:schemas, field: :schema)
               .register_column(:types, field: :type)
               .register_custom_matcher(:has_database?) { |table, db_name|
                 table.databases.include?(db_name)
               }
               .install_filter_methods_on_resource(self, :fetch_dconf_data)

    # Schema-scoped access (primary interface)
    def [](key)
      return nil unless @schema_filter
      get_dconf_setting(@schema_filter, key)
    end

    # Database management methods (Ruby best practice: memoization and safe navigation)
    def active_profile
      @profile_cache ||= detect_active_profile
    end

    private

    def detect_active_profile
      # Use safe command execution with guard clause
      cmd = inspec.command("grep \"^system-db:\" #{@dconf_profile_path} 2>/dev/null")
      return 'local' unless cmd.exit_status == 0 && !cmd.stdout.empty?

      # Use safe navigation and functional programming approach
      databases = cmd.stdout.lines
                     .filter_map { |line| line.split(':')[1]&.strip }
                     .reject(&:empty?)

      databases.first || 'local'
    end

    public

    def system_database
      active_profile
    end

    def available_databases
      cmd = inspec.command("find #{@dconf_db_path}/ -maxdepth 1 -type f 2>/dev/null")
      return [] if cmd.exit_status != 0

      cmd.stdout.lines.map { |line| File.basename(line.strip) }.sort
    end

    # Lock validation methods
    def has_locked?(key)
      return false unless @schema_filter
      locked_setting?(@schema_filter, key)
    end

    def has_locked_setting?(schema, key)
      locked_setting?(clean_schema_name(schema), key)
    end

    def locked_settings
      fetch_lock_data
    end

    # Database consistency checking
    def has_databases_compiled?
      available_databases.all? { |db| database_compiled?(db) }
    end

    def has_database_compiled?(database_name)
      database_compiled?(database_name)
    end

    def databases_needing_update
      available_databases.reject { |db| database_compiled?(db) }
    end

    def has_stale_databases?
      !databases_needing_update.empty?
    end

    # Setting existence in dconf files (not just gsettings runtime)
    def has_setting?(key)
      return false unless @schema_filter
      dconf_setting_exists?(@schema_filter, key)
    end

    # Natural language boolean matchers (building blocks)
    def has_policy_configured?
      !available_databases.empty? && active_profile
    end

    def has_administrative_locks?
      !locked_settings.empty?
    end

    def has_database_consistency?
      has_databases_compiled? && active_profile
    end

    def has_setting_locked?(schema, key)
      locked_setting?(clean_schema_name(schema), key)
    end

    # Security-focused groupings
    def security_locks
      security_patterns = ['lock', 'banner', 'disable', 'automount', 'autorun']
      locked_settings.select do |lock|
        security_patterns.any? { |pattern| lock[:key].include?(pattern) || lock[:path].include?(pattern) }
      end
    end

    def media_handling_locks
      locked_settings.select { |lock| lock[:schema] == 'desktop.media-handling' }
    end

    def login_locks
      locked_settings.select { |lock| lock[:schema] == 'login-screen' }
    end

    def screensaver_locks
      locked_settings.select { |lock| lock[:schema] == 'desktop.screensaver' }
    end

    # Convenience methods for common settings (parameterized schema names)
    def banner_locked?(schema = 'login-screen', key = 'banner-message-enable')
      locked_setting?(clean_schema_name(schema), key)
    end

    def automount_locked?(schema = 'desktop.media-handling', key = 'automount-open')
      locked_setting?(clean_schema_name(schema), key)
    end

    def screensaver_locked?(schema = 'desktop.screensaver', key = 'lock-enabled')
      locked_setting?(clean_schema_name(schema), key)
    end

    def to_s
      @schema_filter ? "Dconf[#{@schema_filter}]" : "Dconf"
    end

    def resource_id
      @schema_filter || "dconf"
    end

    private

    def fetch_dconf_data
      return @database_cache if @database_cache

      @database_cache = []

      available_databases.each do |database|
        database_path = "#{@dconf_db_path}/#{database}"

        # Get settings from database directory
        settings_cmd = inspec.command("find #{database_path}.d/ -name '*.conf' -o -name '*.d' 2>/dev/null | xargs grep -h '^\\[\\|^[^#]' 2>/dev/null")

        if settings_cmd.exit_status == 0
          parse_dconf_settings(settings_cmd.stdout, database)
        end
      end

      @database_cache
    end

    def fetch_lock_data
      return @locks_cache if @locks_cache

      @locks_cache = []

      available_databases.each do |database|
        locks_path = "#{@dconf_db_path}/#{database}.d/locks"

        # Get lock files
        locks_cmd = inspec.command("find #{locks_path}/ -type f 2>/dev/null | xargs cat 2>/dev/null")

        if locks_cmd.exit_status == 0
          parse_lock_files(locks_cmd.stdout, database)
        end
      end

      @locks_cache
    end

    def parse_dconf_settings(content, database)
      current_section = nil

      content.each_line do |line|
        line.strip!
        next if line.empty? || line.start_with?('#')

        if line.match(/^\[(.+)\]$/)
          # Section header like [org/gnome/desktop/screensaver]
          current_section = clean_dconf_path($1)
        elsif line.match(/^(.+?)\s*=\s*(.+)$/) && current_section
          # Setting line like lock-enabled=true
          key = $1.strip
          value = $2.strip

          @database_cache << {
            database: database,
            schema: current_section,
            key: key,
            value: parse_dconf_value(value),
            path: "/org/#{current_section.gsub('.', '/')}/#{key}",
            type: determine_value_type(parse_dconf_value(value))
          }
        end
      end
    end

    def parse_lock_files(content, database)
      content.each_line do |line|
        line.strip!
        next if line.empty? || line.start_with?('#')

        # Lock file entries are paths like /org/gnome/desktop/screensaver/lock-enabled
        if line.start_with?('/org/gnome/')
          path_parts = line.split('/')
          next unless path_parts.length >= 5

          # Extract schema and key from path
          schema_parts = path_parts[3..-2]  # Skip /org/gnome/ and key
          key = path_parts[-1]
          schema = clean_schema_name(schema_parts.join('.'))

          @locks_cache << {
            database: database,
            schema: schema,
            key: key,
            path: line,
            type: 'lock'
          }
        end
      end
    end

    def clean_dconf_path(path)
      # Convert dconf path to schema format
      # /org/gnome/desktop/screensaver → desktop.screensaver
      path.sub(/^org\/gnome\//, '').gsub('/', '.')
    end

    def parse_dconf_value(value)
      # Parse dconf values (similar to gsettings but simpler format)
      case value
      when /^true$|^false$/
        value == 'true'
      when /^\d+$/
        value.to_i
      when /^'([^']*)'$/
        $1
      else
        value.gsub(/^'|'$/, '')  # Remove surrounding quotes
      end
    end

    def determine_value_type(value)
      case value
      when true, false then 'boolean'
      when Integer then 'integer'
      when String then 'string'
      else 'unknown'
      end
    end

    def get_dconf_setting(schema, key)
      clean_schema = clean_schema_name(schema)
      setting = fetch_dconf_data.find { |s| s[:schema] == clean_schema && s[:key] == key }
      setting ? setting[:value] : nil
    end

    def dconf_setting_exists?(schema, key)
      clean_schema = clean_schema_name(schema)
      fetch_dconf_data.any? { |s| s[:schema] == clean_schema && s[:key] == key }
    end

    def locked_setting?(schema, key)
      clean_schema = clean_schema_name(schema)
      fetch_lock_data.any? { |lock| lock[:schema] == clean_schema && lock[:key] == key }
    end

    def database_compiled?(database)
      # Check if database file is newer than source directory
      db_file = "/etc/dconf/db/#{database}"
      db_dir = "/etc/dconf/db/#{database}.d"

      return false unless inspec.file(db_file).exist?
      return true unless inspec.file(db_dir).exist?  # No source dir means compiled is fine

      inspec.file(db_file).mtime >= inspec.file(db_dir).mtime
    end

    def clean_schema_name(schema_name)
      return nil unless schema_name
      schema_name.to_s.sub(/^org\.gnome\./, '')
    end

    def dconf_available?
      cmd = inspec.command('which dconf')
      cmd.exit_status == 0
    end
  end
end