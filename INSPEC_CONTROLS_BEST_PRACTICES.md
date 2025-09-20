# InSpec Controls Best Practices - RHEL 9 STIG Profile

## Context Recovery Summary

This document captures the InSpec control best practices learned during GUI resource development for quick context restoration and future control development.

## Control Structure Best Practices

### 1. Not Applicable (N/A) Handling Patterns

#### Single `only_if` for Primary Conditions
```ruby
# Use only_if for deployment context conditions (containers, cloud, etc.)
only_if('This control is Not Applicable to containers', impact: 0.0) {
  !virtualization.system.eql?('docker')
}

# Combine multiple conditions when you can only use only_if once
only_if('This control is Not Applicable to containers or without GUI', impact: 0.0) {
  !virtualization.system.eql?('docker') && gui.present?
}
```

#### Fast-Failing if/else for Additional N/A Conditions
```ruby
# Use when only_if is already used for deployment context
unless gui.present?
  impact 0.0
  describe 'The system does not have a GUI/desktop environment installed' do
    skip 'A GUI/desktop environment is not installed, this control is Not Applicable.'
  end
end
```

### 2. Impact vs Skip Decision Tree

#### When to Use `impact 0.0`:
- **Deployment context makes control irrelevant** (containers, cloud instances)
- **Required software/hardware not present** (no GUI, package not installed)
- **System configuration makes control impossible** (IPv6 disabled, etc.)

#### When to Use `skip` (Manual Review):
- **Mixed environments requiring human judgment** (GNOME + KDE installed)
- **Organization-specific configurations** (custom security tools)
- **Complex environmental conditions** we can't fully automate

```ruby
# Impact 0.0 - Completely Not Applicable
unless gui.present?
  impact 0.0
  describe 'No GUI environment' do
    skip 'GUI not installed, control Not Applicable'
  end
end

# Skip - Manual Review Required
if gui.has_mixed_environment?
  describe 'Mixed desktop environments detected' do
    skip "Manual verification required for: #{gui.desktop_environments.join(', ')}"
  end
end
```

### 3. Resource Usage Patterns

#### Clean Resource Interface (Our Approach)
```ruby
# Simple, declarative testing
describe gnome_settings('desktop.screensaver') do
  its('lock_enabled') { should cmp true }
end

# Natural language matchers
describe gnome_settings do
  it { should have_setting_enabled('desktop.screensaver', 'lock-enabled') }
end

# Combined validation (value + policy)
describe gnome_settings do
  it { should have_enforced_setting('login-screen', 'banner-message-enable', true) }
end
```

#### Avoid Complex Nested Logic (PR #93 Issues)
```ruby
# BAD - Complex nested conditionals (PR #93 style)
g = guis(input('possibly_installed_guis'))
gs = gsettings('banner-message-enable', 'org.gnome.login-screen')

if g.has_gui?
  if g.has_non_gnome_gui?
    if g.has_gnome_gui? && !gs.set?('true')
      describe gs do
        it 'should be true.' do
          expect(subject).to be_set('true'), "error message..."
        end
      end
    end
    # ... more nested logic
  end
end

# GOOD - Clean resource interface
describe gnome_settings('login-screen') do
  its('banner_message_enable') { should cmp true }
end
```

## GUI-Specific Control Patterns

### 1. GUI Detection Best Practices

#### Use Resources, Not Manual Commands
```ruby
# BAD - Brittle file system checks
no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

# BAD - Single package assumption
if package('gnome-desktop3').installed?

# GOOD - Comprehensive GUI detection
only_if('Control requires GUI environment', impact: 0.0) {
  gui.present?
}
```

#### Handle Mixed Environments Gracefully
```ruby
# Check for mixed environments when needed
if gui.has_mixed_environment?
  describe 'Mixed desktop environments detected' do
    skip "Manual verification required for: #{gui.desktop_environments.join(', ')}"
  end
end

# Or focus on specific desktop type
only_if('Control requires GNOME desktop', impact: 0.0) {
  gui.gnome?
}
```

### 2. GNOME Settings Testing Patterns

#### Schema-Based Organization
```ruby
# Group related settings by schema
describe gnome_settings('desktop.screensaver') do
  its('lock_enabled') { should cmp true }
  its('lock_delay') { should cmp <= input('screensaver_lock_delay') }
  its('picture_uri') { should be_empty }
end

# Separate schemas for different functional areas
describe gnome_settings('login-screen') do
  its('banner_message_enable') { should cmp true }
  its('disable_user_list') { should cmp true }
end
```

#### Policy Enforcement Validation
```ruby
# Check both runtime value AND administrative lock
describe gnome_settings do
  it { should have_enforced_setting('schema', 'key', expected_value) }
end

# Or check separately for clarity
describe gnome_settings('schema') do
  its('key') { should cmp expected_value }
end

describe dconf('schema') do
  it { should have_locked('key') }
end
```

## Control Refactoring Patterns

### Before vs After Examples

#### Simple Screensaver Control
```ruby
# BEFORE (11 lines)
if package('gnome-desktop3').installed?
  describe command('gsettings get org.gnome.desktop.screensaver lock-enabled') do
    its('stdout.strip') { should cmp 'true' }
  end
else
  impact 0.0
  describe 'The system does not have GNOME installed' do
    skip "Not Applicable"
  end
end

# AFTER (3 lines + proper only_if)
only_if('Control requires GUI', impact: 0.0) { gui.present? }

describe gnome_settings('desktop.screensaver') do
  its('lock_enabled') { should cmp true }
end
```

#### Complex Banner Control
```ruby
# BEFORE PR #93 (40+ lines of nested conditionals)
g = guis(input('possibly_installed_guis'))
gs = gsettings('banner-message-enable', 'org.gnome.login-screen')
if g.has_gui?
  if g.has_non_gnome_gui?
    # ... complex nested logic
  end
end

# AFTER (5 lines)
only_if('Control requires GUI', impact: 0.0) { gui.present? }

describe gnome_settings('login-screen') do
  its('banner_message_enable') { should cmp true }
end
```

## Code Quality Guidelines

### 1. No Unnecessary Comments in Controls
```ruby
# BAD - Cluttered with implementation comments
# IMPROVED: Using best-practice resources
# Replaces manual file parsing with clean resource interface
describe gnome_settings('schema') do

# GOOD - Clean, focused code
describe gnome_settings('schema') do
  its('key') { should cmp value }
end
```

### 2. Consistent Language and Terminology
```ruby
# Use consistent terminology across controls
'GUI/desktop environment'           # Not 'GUI Desktop' or 'graphical interface'
'Not Applicable'                    # Not 'N/A' or 'not applicable'
'Manual verification required'      # For human review cases
```

### 3. Resource Integration Best Practices
```ruby
# Leverage resource composition
describe gnome_settings('schema') do
  its('setting') { should cmp value }              # Value check
end

describe dconf('schema') do
  it { should have_locked('setting') }             # Policy enforcement
end

# Or combined validation
describe gnome_settings do
  it { should have_enforced_setting('schema', 'setting', value) }
end
```

## Performance Considerations

### 1. Resource Efficiency
```ruby
# GOOD - Single resource instance per control
settings = gnome_settings('desktop.screensaver')
describe settings do
  its('lock_enabled') { should cmp true }
  its('lock_delay') { should cmp <= 5 }
end

# AVOID - Multiple resource instantiations
describe gnome_settings('desktop.screensaver') do
  its('lock_enabled') { should cmp true }
end
describe gnome_settings('desktop.screensaver') do  # Redundant!
  its('lock_delay') { should cmp <= 5 }
end
```

### 2. Conditional Logic Optimization
```ruby
# Use only_if to skip expensive operations entirely
only_if('Skip if GUI not present', impact: 0.0) {
  gui.present?  # Fast check prevents gsettings execution
}
```

## Input Handling Best Practices

### 1. Don't Change Input Names Unless Necessary
```ruby
# GOOD - Use existing inputs
describe gnome_settings('desktop.session') do
  its('idle_delay') { should cmp <= input('system_inactivity_timeout') }  # Existing input
end

# BAD - Changing input names without updating inspec.yml
describe gnome_settings('desktop.session') do
  its('idle_delay') { should cmp <= input('graphical_user_session_inactivity_timeout') }  # Doesn't exist!
end
```

### 2. When You Must Add New Inputs

**Process:**
1. **Add to inspec.yml first** with good defaults
2. **Document the control reference** (which SV- numbers use it)
3. **Provide sensible defaults** for common use cases
4. **Update control to use new input**

**inspec.yml format:**
```yaml
# SV-258XXX
- name: new_input_name
  description: Clear description of what this controls
  type: String  # or Numeric, Boolean, Array, Hash
  value: "sensible_default_value"
```

### 3. Input Reference Patterns
```ruby
# Use existing profile inputs when available
describe gnome_settings do
  it { should have_valid_timeout('desktop.session', 'idle-delay',
                                 input('system_inactivity_timeout')) }  # Existing
end

# Resource provides defaults for quick testing
describe gnome_settings do
  it { should have_delay }  # Uses resource default
  it { should have_delay(input('screensaver_lock_delay')) }  # Uses profile input
end
```

### 4. Input Change Process (When Absolutely Necessary)

**Step 1: Check if existing input works**
```bash
# Search existing inputs first
rg "timeout|delay|banner" inspec.yml
```

**Step 2: Add to inspec.yml with good defaults**
```yaml
# SV-258XXX, SV-258YYY
- name: new_setting_name
  description: Maximum timeout for graphical sessions in seconds
  type: Numeric
  value: 900  # Sensible STIG-compliant default
```

**Step 3: Update control to use new input**
```ruby
describe gnome_settings('schema') do
  its('setting') { should cmp <= input('new_setting_name') }
end
```

**Critical Rule: Never reference non-existent inputs in controls!**

### 5. Common Existing Inputs to Reuse First
```ruby
# Timeouts and delays (check these before creating new ones)
input('system_inactivity_timeout')           # Session timeouts
input('screensaver_lock_delay')              # Lock delays
input('client_alive_interval')               # Network timeouts

# Security settings
input('smart_card_enabled')                  # Smartcard features
input('banner_message_text_cli')             # Banner text
input('multifactor_enabled')                 # MFA requirements

# Operational requirements
input('gui_automount_required')              # Media handling exceptions
input('gui_autorun_required')                # Autorun exceptions
input('gui_autorun_writable_required')       # Autorun override exceptions
```

## Migration Guidelines

### 1. Control Update Process
1. **Identify GUI detection logic** - replace with `gui.present?`
2. **Replace raw gsettings commands** - use `gnome_settings('schema')`
3. **Consolidate with only_if** - combine N/A conditions where possible
4. **Remove unnecessary comments** - keep code clean and focused
5. **Test functionality** - ensure same test outcomes

### 2. Backward Compatibility
- **Preserve all metadata** (tags, descriptions, impact levels)
- **Maintain test outcomes** - controls should pass/fail the same way
- **Keep manual review cases** - don't over-automate where human judgment needed

## Control Development Standards

### 1. New Control Template
```ruby
control 'SV-XXXXXX' do
  title 'Control title'
  desc 'Description...'
  desc 'check', 'Check procedure...'
  desc 'fix', 'Fix procedure...'
  impact 0.5
  # ... tags ...

  only_if('Not Applicable condition', impact: 0.0) {
    deployment_condition && gui.present?  # Combine when possible
  }

  # Clean resource-based testing
  describe resource('parameter') do
    its('property') { should cmp expected_value }
  end
end
```

### 2. Quality Checklist
- [ ] Uses `only_if` for deployment context N/A conditions
- [ ] Handles GUI detection with `gui.present?`
- [ ] Uses appropriate resources instead of raw commands
- [ ] Natural language matchers where applicable
- [ ] No unnecessary implementation comments
- [ ] Consistent terminology and messaging
- [ ] Input parameterization for flexibility
- [ ] Proper impact vs skip for different N/A types

This document ensures consistent, high-quality control development following established InSpec and RHEL profile patterns.