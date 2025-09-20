# InSpec Core Resource Patterns - LLM Reference Guide

## Overview
This document captures the standard patterns used in InSpec core resources for implementing high-quality, consistent resources. Use this as a reference when building new resources.

## Core Resource Structure Patterns

### 1. Basic Resource Template
```ruby
require "inspec/utils/filter"  # If using FilterTable
require "inspec/utils/file_reader"  # If reading files
require "hashie"  # If using Mash for dot notation

module Inspec::Resources
  class ResourceName < Inspec.resource(1)
    name "resource_name"
    supports platform: "unix"  # or "windows", "linux", etc.
    desc "Description of what the resource does"
    example <<~EXAMPLE
      describe resource_name('parameter') do
        it { should be_property }
        its('attribute') { should eq 'value' }
      end
    EXAMPLE

    def initialize(param)
      @param = param
      # Platform-specific initialization
    end

    def to_s
      "Resource Description[#{@param}]"
    end

    def resource_id  # Optional but recommended
      @param
    end
  end
end
```

## Platform-Specific Implementation Patterns

### Pattern 1: Platform Selection in Initialize (Package Resource Style)
```ruby
class Package < Inspec.resource(1)
  def initialize(package_name, opts = {})
    @package_name = package_name
    os = inspec.os

    if os.debian?
      @pkgman = Deb.new(inspec)
    elsif os.redhat? || %w{suse amazon fedora}.include?(os[:family])
      @pkgman = Rpm.new(inspec, opts)
    elsif os.windows?
      @pkgman = WindowsPkg.new(inspec)
    else
      raise Inspec::Exceptions::ResourceSkipped, "Unsupported platform"
    end
  end

  def installed?
    @pkgman.installed?(@package_name)
  end
end
```

### Pattern 2: Platform Selector Module (User Resource Style)
```ruby
module UserManagementSelector
  def select_user_manager(os)
    if os.linux?
      LinuxUser.new(inspec)
    elsif os.windows?
      WindowsUser.new(inspec)
    elsif ["darwin"].include?(os[:family])
      DarwinUser.new(inspec)
    end
  end
end

class User < Inspec.resource(1)
  include UserManagementSelector

  def initialize(username)
    @user_provider = select_user_manager(inspec.os)
  end
end
```

### Pattern 3: Simple Inheritance (EtcHostsAllow Style)
```ruby
class EtcHostsAllow < Inspec.resource(1)
  name "etc_hosts_allow"
  supports platform: "unix"

  def initialize(hosts_allow_path = nil)
    @conf_path = hosts_allow_path || "/etc/hosts.allow"
    read_content
  end

  # Shared implementation
end

class EtcHostsDeny < EtcHostsAllow
  name "etc_hosts_deny"
  supports platform: "unix"

  def initialize(path = nil)
    return skip_resource "`etc_hosts_deny` is not supported on your OS" unless inspec.os.linux?
    super(path || "/etc/hosts.deny")
  end

  def to_s
    "hosts.deny Configuration"
  end
end
```

## FilterTable Implementation Patterns

### Standard FilterTable Setup
```ruby
class Processes < Inspec.resource(1)
  # 1. Create FilterTable instance
  filter = FilterTable.create

  # 2. Register columns
  filter.register_column(:labels, field: "label")
        .register_column(:pids, field: "pid")
        .register_column(:users, field: "user")
        .register_column(:commands, field: "command")

  # 3. Install filter methods
  filter.install_filter_methods_on_resource(self, :filtered_processes)

  def initialize(grep = /.*/)
    @list = fetch_data_matching(grep)
  end

  private

  # 4. Data fetching method (returns array of hashes)
  def filtered_processes
    @list  # Array of hashes with keys matching registered columns
  end
end
```

### FilterTable with Custom Matchers
```ruby
filter = FilterTable.create
filter.register_column(:names, field: "name")
      .register_column(:versions, field: "version")
      .register_custom_matcher(:installed?) { |table|
        table.entries.any?
      }
      .register_custom_matcher(:has_version?) { |table, version|
        table.versions.include?(version)
      }
```

## Property Accessor Patterns

### Direct Property Delegation (File Resource Style)
```ruby
class FileResource < Inspec.resource(1)
  # Mass delegation to backend
  %w{
    type exist? file? directory? symlink? pipe?
    mode owner group mtime size
  }.each do |m|
    define_method m.to_sym do |*args|
      file.method(m.to_sym).call(*args)
    end
  end
end
```

### Conditional Property Access
```ruby
def installed?
  return false if @pkgman.nil?
  @pkgman.installed?(@package_name)
end

def version
  return nil unless installed?
  @pkgman.version(@package_name)
end
```

### Cached Property Pattern
```ruby
def info
  return @cache if @cache
  @cache = @pkgman.info(@package_name)
end
```

## Error Handling and Skip Patterns

### Platform Support Checks
```ruby
def initialize(path = nil)
  return skip_resource "`resource` is not supported on your OS" unless inspec.os.linux?
  super(path)
end
```

### Graceful Failure Patterns
```ruby
def command_result
  @result ||= inspec.command("some-command")
  return nil if @result.exit_status != 0
  @result.stdout
end
```

### Resource Skipping
```ruby
# In initialize
return skip_resource "Reason for skipping" unless condition

# In methods
def some_property
  return nil unless available?
  # ... implementation
end
```

## Naming and Interface Conventions

### Resource Naming
- **Singular resources**: `package`, `file`, `service` (test specific instances)
- **Plural resources**: `users`, `processes`, `packages` (test collections)
- **Configuration resources**: `apache_conf`, `nginx_conf` (test config files)

### Method Naming
- **Boolean methods**: End with `?` (e.g., `installed?`, `enabled?`, `running?`)
- **Property accessors**: Noun forms (e.g., `version`, `owner`, `mode`)
- **State checkers**: `be_*` methods for RSpec matchers (e.g., `be_installed`)

### Parameter Conventions
```ruby
# Required parameter first, optional parameters as hash
def initialize(name, opts = {})

# Default values for optional parameters
def initialize(path = nil)
  @path = path || default_path
end
```

## Module and Mixin Patterns

### Utility Modules
```ruby
module FilePermissionsSelector
  def select_file_perms_style(os)
    if os.unix?
      UnixFilePermissions.new(inspec)
    elsif os.windows?
      WindowsFilePermissions.new(inspec)
    end
  end
end

class FileResource < Inspec.resource(1)
  include FilePermissionsSelector

  def initialize(path)
    @perms_provider = select_file_perms_style(inspec.os)
  end
end
```

### Common Utility Includes
```ruby
include Inspec::Utils::CommentParser  # For parsing config files with comments
include FileReader                    # For reading file content safely
include Inspec::Utils::LinuxMountParser  # For parsing mount information
```

## Performance and Caching Patterns

### Lazy Loading Pattern
```ruby
def expensive_operation
  @cache ||= perform_expensive_operation
end
```

### Batch Data Fetching (Processes Style)
```ruby
def initialize(grep = /.*/)
  # Fetch all data once, filter in memory
  all_data = fetch_all_processes
  @list = all_data.select { |process| matches_filter(process, grep) }
end
```

## Platform Detection Patterns

### OS Family Checks
```ruby
if inspec.os.linux?
elsif inspec.os.windows?
elsif inspec.os.darwin?
elsif inspec.os.unix?  # Broader than linux
end
```

### Specific Distribution Checks
```ruby
if os.debian?
elsif os.redhat?
elsif %w{suse amazon fedora}.include?(os[:family])
end
```

## Advanced Patterns

### Custom Data Structures (Service Resource Style)
```ruby
class Runlevels < Hash
  attr_accessor :owner

  def self.from_hash(owner, hash = {}, filter = nil)
    res = Runlevels.new(owner)
    # ... filtering logic
    res
  end

  def enabled?
    values.all?
  end

  def disabled?
    values.none?
  end
end
```

### Property Chaining
```ruby
def runlevels(filter = nil)
  Runlevels.from_hash(self, get_runlevels, filter)
end
```

## Testing and Validation Patterns

### Resource Validation
```ruby
def resource_id
  @conf_path || @package_name || @identifier
end

def to_s
  "Descriptive Name[#{@identifier}]"
end
```

### Boolean Matcher Support
```ruby
# Methods ending in ? automatically get be_* matchers
def installed?  # Enables: it { should be_installed }
def enabled?    # Enables: it { should be_enabled }
def running?    # Enables: it { should be_running }
```

## Additional Core Patterns Discovered

### Resource Inheritance Patterns

#### Simple Extension (Directory extends File)
```ruby
class Directory < FileResource
  name "directory"

  def exist?
    file.exist? && file.directory?  # Override parent behavior
  end

  def to_s
    "Directory #{source_path}"
  end
end
```

#### Deprecation Pattern (LinuxKernelParameter)
```ruby
class LinuxKernelParameter < KernelParameter
  def initialize(parameter)
    Inspec.deprecate(:resource_linux_kernel_parameter, "Use `kernel_parameter` instead")
    super(parameter)
  end

  def value
    Inspec.deprecate(:resource_linux_kernel_parameter, "Use `kernel_parameter` instead")
    super()
  end
end
```

### Parameter Handling Patterns

#### Required + Optional Hash Parameters
```ruby
def initialize(package_name, opts = {})
  @package_name = package_name  # Required
  @location = opts[:path]       # Optional
  @timeout = opts[:timeout]     # Optional
end
```

#### Multiple Constructor Patterns (Registry Key)
```ruby
# Three different ways to initialize:
# 1. registry_key('path')
# 2. registry_key('name', 'path')
# 3. registry_key({name: 'name', hive: 'hive', key: 'key'})
def initialize(*args)
  case args.length
  when 1
    # Handle single argument (path or hash)
  when 2
    # Handle name, path arguments
  end
end
```

### Performance and Caching Patterns

#### Lazy Loading with Instance Variable Check
```ruby
def info
  return @info if defined?(@info)  # More explicit than @info ||=
  @info = expensive_operation
end
```

#### Smart Caching
```ruby
def expensive_data
  @cache ||= fetch_expensive_data
end

# Reset cache when needed
def reload!
  @cache = nil
end
```

### Platform-Specific Command Handling

#### Command Path Selection (Kernel Module)
```ruby
def modinfo_cmd_for_os
  if inspec.os.redhat? || inspec.os.name == "fedora"
    "/sbin/modinfo"
  else
    "modinfo"
  end
end

def loaded?
  lsmod_cmd = inspec.os.redhat? ? "/sbin/lsmod" : "lsmod"
  cmd = inspec.command(lsmod_cmd)
  # ... use cmd
end
```

#### Cross-Platform Command Building (NPM)
```ruby
def build_command
  if @location
    separator = inspec.os.platform?("windows") ? ";" : "&&"
    invocation = "cd #{Shellwords.escape @location} #{separator} npm"
  else
    invocation = "npm -g"
  end

  unless inspec.os.platform?("windows")
    invocation = "sh -c '#{invocation}'"  # Protect against sudo issues
  end
end
```

### FilterTable Advanced Patterns

#### Multiple Column Styles
```ruby
filter.register_column(:statuses, field: "status", style: :simple)  # Simple array
      .register_column(:names, field: "name")                       # Standard
      .register_column(:versions, field: "version")                 # Standard
```

#### Custom Properties vs Custom Matchers
```ruby
# Custom matcher (returns boolean)
.register_custom_matcher(:installed?) { |table|
  table.entries.any?
}

# Custom property (returns value)
.register_custom_property(:total_count) { |table|
  table.entries.length
}
```

### Error Handling Best Practices

#### Resource Skipping Patterns
```ruby
# In initialize
return skip_resource "Resource not supported on #{inspec.os.name}" unless supported?

# With detailed message
return skip_resource "`#{resource_name}` is not supported on your OS." unless inspec.os.linux?
```

#### Graceful Command Failure
```ruby
def value
  cmd = inspec.command("some-command")
  return nil if cmd.exit_status != 0  # Don't fail, return nil
  cmd.stdout.chomp.strip
end
```

#### Input Validation
```ruby
def initialize(cmd, options = {})
  if cmd.nil?
    raise "InSpec `command` was called with `nil`. Please provide a valid command."
  end
  @command = cmd
end
```

### Boolean Method Patterns

#### Standard Boolean Naming
```ruby
def loaded?      # State checks
def enabled?     # Configuration checks
def installed?   # Existence checks
def blacklisted? # Policy checks
def running?     # Active state checks
```

#### RSpec Automatic Predicate Matchers
**Key Insight**: RSpec automatically creates matchers for predicate methods:

```ruby
# Method ending with ? → Automatic matcher
def valid?           # → it { should be_valid }
def empty?           # → it { should be_empty }
def present?         # → it { should be_present }
def has_setting?     # → it { should have_setting }
def has_content?     # → it { should have_content }
def has_banner?      # → it { should have_banner }
```

**Natural Language Design**:
- **`be_*` matchers**: For states/conditions (`be_enabled`, `be_configured`)
- **`have_*` matchers**: For possession/content (`have_setting`, `have_content`)

**Examples**:
```ruby
# Resource methods
def configured?           # State
def has_setting?(key)     # Possession
def has_content?(text)    # Content

# Usage in controls
describe resource do
  it { should be_configured }           # "should be configured"
  it { should have_setting('key') }     # "should have setting"
  it { should have_content('text') }    # "should have content"
end
```

**Benefits**:
- More human-readable tests
- Better failure messages
- Natural English flow
- Less robotic syntax

#### Avoid Hard-Coded Values in Resources
**Problem**: Hard-coding limits breaks flexibility
```ruby
# BAD - hard-coded value
def secure_screensaver?
  delay <= 5  # What if requirement is 10 seconds?
end

# GOOD - parameterized with sensible default
def has_delay?(max_delay = 5)
  delay <= max_delay
end
```

**Usage**:
```ruby
# Use default (quick testing)
it { should have_delay }

# Use custom value (organization requirements)
it { should have_delay(input('screensaver_lock_delay')) }

# Use specific value (edge case testing)
it { should have_delay(10) }
```

**Principle**: Resource provides **building blocks**, control defines **requirements**.

### InSpec Interface Grammar Best Practices

#### RSpec Automatic Matcher Grammar Rules

**Core Pattern**: Method name determines matcher syntax and natural language flow

```ruby
# POSSESSION/CONTENT: has_* methods → have_* matchers
def has_setting?(key)           # → it { should have_setting('key') }
def has_exact_content?(text)    # → it { should have_exact_content(text) }
def has_banner_configured?      # → it { should have_banner_configured }
def has_setting_locked?(s, k)   # → it { should have_setting_locked(s, k) }

# SIMPLE STATE: * methods → be_* matchers
def enabled?                    # → it { should be_enabled }
def present?                    # → it { should be_present }
def configured?                 # → it { should be_configured }
```

#### Natural Language Flow Guidelines

**Choose method names based on how they read in English:**

```ruby
# GOOD - Natural English flow
describe resource do
  it { should have_exact_content('text') }        # "should have exact content"
  it { should have_setting_enabled('s', 'k') }   # "should have setting enabled"
  it { should have_banner_configured }           # "should have banner configured"
  it { should be_present }                       # "should be present"
  it { should be_enabled }                       # "should be enabled"
end

# BAD - Awkward English flow
describe resource do
  it { should be_exact_content('text') }         # "should be exact content" ❌
  it { should be_setting_enabled('s', 'k') }    # "should be setting enabled" ❌
  it { should have_enabled }                     # "should have enabled" ❌
end
```

#### Consistency Guidelines

**1. Possession/Content → `has_*` pattern:**
- Settings existence: `has_setting?`, `has_schema?`
- Content validation: `has_exact_content?`, `has_valid_timeout?`
- Complex state: `has_banner_configured?`, `has_policy_configured?`

**2. Simple State → direct predicate:**
- Basic conditions: `enabled?`, `present?`, `installed?`
- Status checks: `running?`, `loaded?`, `available?`

**3. Parameter Handling:**
```ruby
# GOOD - Clear parameter purpose
def has_valid_timeout?(schema, key, max_timeout, options = {})

# BAD - Unclear parameter order
def timeout_valid?(max_timeout, schema, key)
```

#### Common Grammar Mistakes to Avoid

```ruby
# MISTAKE: Mixing possession and state patterns
def has_enabled?           # ❌ "have enabled" (incomplete)
def setting_has_value?     # ❌ "be setting has value" (awkward)

# CORRECT: Consistent patterns
def has_setting_enabled?   # ✅ "have setting enabled"
def enabled?               # ✅ "be enabled"

# MISTAKE: Overly verbose method names
def has_setting_that_is_locked_and_enabled?  # ❌ Too verbose

# CORRECT: Focused, single-purpose methods
def has_setting_locked?    # ✅ Check one thing
def has_setting_enabled?   # ✅ Check another thing
def has_enforced_setting?  # ✅ Check both (with clear intent)
```

#### Documentation Examples

**Always include natural language examples in documentation:**

```ruby
example <<~EXAMPLE
  # Natural language flow - reads like English
  describe resource do
    it { should have_exact_content(input('text')) }    # "should have exact content"
    it { should have_setting_enabled('schema', 'key') } # "should have setting enabled"
    it { should be_configured }                         # "should be configured"
  end
EXAMPLE
```

#### Complex Boolean Logic
```ruby
def running?
  # Complex platform-specific logic with fallbacks
  states.any? && !!(states[0] =~ /True/ || states[0] =~ /^R+/ || states[0] =~ /^S+/)
end

def disabled?
  !modprobe_output.match(%r{^install\s+#{@module}\s+/(s?)bin/(true|false)}).nil?
end
```

### Value Processing Patterns

#### Type Coercion (Kernel Parameter)
```ruby
def value
  cmd = inspec.command("/sbin/sysctl -q -n #{@parameter}")
  return nil if cmd.exit_status != 0

  # Clean and convert
  result = cmd.stdout.chomp.strip
  result = result.to_i if result =~ /^\d+$/  # Auto-convert integers
  result
end
```

#### Safe Command Execution
```ruby
def info
  return @info if defined?(@info)

  cmd = inspec.command("command-here")
  @info = if cmd.exit_status == 0
           parse_output(cmd.stdout)
          else
           default_values
          end
end
```

## Critical Implementation Principles

### 1. Resource Identification Requirements
```ruby
def resource_id
  @primary_identifier || "Resource Type"  # Required for debugging
end

def to_s
  "Descriptive Name[#{@identifier}]"      # Required for test output
end
```

### 2. Platform Support Declaration
```ruby
supports platform: "unix"      # Broad platform support
supports platform: "linux"     # Specific OS family
supports platform: "windows"   # Windows support
# Multiple supports declarations are allowed
```

### 3. Documentation Requirements
```ruby
desc "Clear description of what the resource does"
example <<~EXAMPLE
  # Real, working examples that users can copy
  describe resource_name('param') do
    it { should be_property }
    its('attribute') { should eq 'value' }
  end
EXAMPLE
```

### 4. Module Organization
```ruby
module Inspec::Resources
  class ResourceName < Inspec.resource(1)
    # All resources must be in this module
    # Class name should match file name
  end
end
```

## Key Takeaways for GUI Resources

### 1. Follow Package Resource Pattern for Platform Detection
```ruby
class Gui < Inspec.resource(1)
  name "gui"
  supports platform: "unix"
  supports platform: "windows"

  def initialize
    os = inspec.os
    if os.linux?
      @implementation = LinuxGui.new(inspec)
    elsif os.windows?
      @implementation = WindowsGui.new(inspec)
    elsif os.darwin?
      @implementation = DarwinGui.new(inspec)
    else
      return skip_resource "GUI detection not supported on #{os.family}"
    end
  end

  # Delegate to platform implementation
  def present?; @implementation.present?; end
  def desktop_environments; @implementation.desktop_environments; end
end
```

### 2. Follow Processes Pattern for FilterTable Collections
```ruby
class GnomeSettings < Inspec.resource(1)
  name "gnome_settings"
  supports platform: "linux"

  def initialize(schema = nil)
    @schema_filter = schema
    return skip_resource "gsettings not available" unless gsettings_available?

    # Fetch data once like processes resource
    all_settings = fetch_all_settings
    @list = @schema_filter ? filter_by_schema(all_settings) : all_settings
  end

  filter = FilterTable.create
  filter.register_column(:schemas, field: "schema")
        .register_column(:keys, field: "key")
        .register_column(:values, field: "value")
        .install_filter_methods_on_resource(self, :filtered_settings)

  private

  def filtered_settings
    @list
  end
end
```

### 3. Follow Kernel Parameter Pattern for Simple Property Access
```ruby
# Clean, simple property access with proper error handling
def [](key)
  return nil unless @schema_filter

  setting = @list.find { |s| s[:key] == key }
  setting ? setting[:value] : nil
end
```

This comprehensive pattern guide ensures our GUI resources will follow all InSpec core conventions and best practices!
  name "gui"
  supports platform: "unix"
  supports platform: "windows"

  def initialize
    @implementation = case inspec.os.family
                     when 'linux' then LinuxGui.new(inspec)
                     when 'windows' then WindowsGui.new(inspec)
                     when 'darwin' then DarwinGui.new(inspec)
                     else skip_resource "Unsupported platform"
                     end
  end

  # Delegate to platform implementation
  def present?; @implementation.present?; end
  def desktop_environments; @implementation.desktop_environments; end
end

class LinuxGui < Gui
  # Linux-specific implementation
end
```

### 2. Use FilterTable for Collection Resources
```ruby
class GnomeSettings < Inspec.resource(1)
  filter = FilterTable.create
  filter.register_column(:schemas, field: "schema")
        .register_column(:keys, field: "key")
        .register_column(:values, field: "value")
        .install_filter_methods_on_resource(self, :fetch_settings_data)
end
```

### 3. Follow Standard Naming and Interface Conventions
- Schema-scoped: `gnome_settings('desktop.screensaver')`
- Boolean methods: `present?`, `enabled?`, `locked?`
- Property access: `its('lock-delay')`, not `its('get_lock_delay')`
- Resource identification: `to_s` and `resource_id` methods

This patterns guide gives us the exact templates to follow for implementing our GUI resources properly!