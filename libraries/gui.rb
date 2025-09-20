module Inspec::Resources
  class Gui < Inspec.resource(1)
    name "gui"
    supports platform: "unix"
    supports platform: "windows"
    desc "Use the gui InSpec audit resource to test for GUI desktop environments across platforms."

    example <<~EXAMPLE
      # Natural language matchers (follow grammar rules)
      describe gui do
        it { should be_present }                    # "should be present"
        it { should be_gnome }                      # "should be gnome"
        it { should have_sessions }                 # "should have sessions"
        it { should have_mixed_environment }        # "should have mixed environment"
        its('desktop_environments') { should include 'gnome' }
        its('display_manager') { should eq 'gdm' }
      end
    EXAMPLE

    attr_reader :implementation

    def initialize
      @implementation = case inspec.os.family
                       when 'redhat', 'fedora', 'debian', 'suse', 'arch', 'linux'
                         LinuxGui.new(inspec)
                       when 'windows'
                         WindowsGui.new(inspec)
                       when 'darwin'
                         DarwinGui.new(inspec)
                       else
                         return skip_resource "GUI detection not supported on #{inspec.os.family}"
                       end
    end

    # Standard interface - delegated to platform implementation
    def present?
      @implementation.present?
    end

    def desktop_environments
      @implementation.desktop_environments
    end

    def display_manager
      @implementation.display_manager
    end

    def gui_packages
      @implementation.gui_packages
    end

    # Additional methods for STIG use cases
    def gnome?
      desktop_environments.include?('gnome')
    end

    def kde?
      desktop_environments.include?('kde')
    end

    def xfce?
      desktop_environments.include?('xfce')
    end

    def has_mixed_environment?
      desktop_environments.length > 1
    end

    # Alias for backward compatibility
    def mixed_environment?
      has_mixed_environment?
    end

    # Check for desktop session files
    def has_sessions?
      @implementation.has_sessions?
    end

    def to_s
      "GUI Environment"
    end

    def resource_id
      "gui"
    end
  end

  # Linux-specific GUI detection implementation
  class LinuxGui < Gui
    attr_reader :cache  # Useful for debugging detection results

    def initialize(inspec_instance)
      @inspec = inspec_instance
      @cache = nil
    end

    def present?
      !desktop_environments.empty?
    end

    def desktop_environments
      return @cache[:desktop_environments] if @cache
      detect_gui_info
      @cache[:desktop_environments]
    end

    def display_manager
      return @cache[:display_manager] if @cache
      detect_gui_info
      @cache[:display_manager]
    end

    def gui_packages
      return @cache[:gui_packages] if @cache
      detect_gui_info
      @cache[:gui_packages]
    end

    def has_sessions?
      # Check for desktop session files (X11 and Wayland on Linux)
      xsessions_cmd = @inspec.command('ls -1 /usr/share/xsessions/ 2>/dev/null')
      wayland_cmd = @inspec.command('ls -1 /usr/share/wayland-sessions/ 2>/dev/null')
      (xsessions_cmd.exit_status == 0 && !xsessions_cmd.stdout.strip.empty?) ||
        (wayland_cmd.exit_status == 0 && !wayland_cmd.stdout.strip.empty?)
    end

    private

    def detect_gui_info
      @cache = {
        desktop_environments: [],
        display_manager: nil,
        gui_packages: []
      }

      # Common GUI packages to check
      gui_package_map = {
        'gnome-shell' => 'gnome',
        'gnome-desktop3' => 'gnome',
        'gnome-desktop4' => 'gnome',
        'gdm' => 'gnome',
        'plasma-desktop' => 'kde',
        'kde-workspace' => 'kde',
        'sddm' => 'kde',
        'xfce4-session' => 'xfce',
        'lightdm' => 'lightdm',
        'lxde-common' => 'lxde',
        'mate-desktop' => 'mate',
        'cinnamon' => 'cinnamon'
      }

      installed_packages = []
      gui_package_map.each do |package, environment|
        if @inspec.package(package).installed?
          installed_packages << package
          @cache[:desktop_environments] << environment unless @cache[:desktop_environments].include?(environment)

          # Determine display manager
          case package
          when 'gdm'
            @cache[:display_manager] = 'gdm'
          when 'sddm'
            @cache[:display_manager] = 'sddm'
          when 'lightdm'
            @cache[:display_manager] = 'lightdm'
          end
        end
      end

      @cache[:gui_packages] = installed_packages
      @cache[:desktop_environments].uniq!
    end
  end

  # Windows GUI detection (placeholder for future)
  class WindowsGui < Gui

    def initialize(inspec_instance)
      @inspec = inspec_instance
    end

    def present?
      true  # Windows always has GUI
    end

    def desktop_environments
      ['windows']
    end

    def display_manager
      'dwm'
    end

    def gui_packages
      []  # Not applicable for Windows
    end

    def has_sessions?
      true  # Windows always has desktop sessions
    end
  end

  # macOS GUI detection (placeholder for future)
  class DarwinGui < Gui

    def initialize(inspec_instance)
      @inspec = inspec_instance
    end

    def present?
      true  # macOS always has GUI
    end

    def desktop_environments
      ['aqua']
    end

    def display_manager
      'windowserver'
    end

    def gui_packages
      []  # Not applicable for macOS
    end

    def has_sessions?
      true  # macOS always has desktop sessions
    end
  end
end