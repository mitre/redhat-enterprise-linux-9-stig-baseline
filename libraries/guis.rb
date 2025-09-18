class GUIs < Inspec.resource(1)
  name 'guis'

  supports platform: 'redhat', release: '9.*'

  desc 'Use the guis InSpec audit resource to test for the existence of GUI desktop environments.  This is mostly a utility resource to handle requirements that differ when a GNOME desktop environment is available.'
  example <<~EXAMPLE
    g = guis(input('possibly_installed_guis'))
    if g.has_gui?
      describe command('ls -w 1 /usr/share/xsessions')
        its('stdout.strip.lines.count') { should be > 0 }
      end
    else
      describe 'No .desktop files detected.' do
        skip 'Manual check required.'
      end
    end
  EXAMPLE

  # `possibly_installed_guis` must be an array of packages whose installation would count as proof that a GUI desktop environment was installed
  def initialize(possibly_installed_guis)
    @user_specified_packages = possibly_installed_guis
  end

  def installed_guis()
    user_specified_installed_packages = @user_specified_packages.select do |package|
      inspec.package(package).installed?
    end

    desktop_files_to_packages_command = inspec.command('ls -w 1 /usr/share/xsessions/ | xargs -I{} rpm -qf /usr/share/xsessions/{} --qf "%{NAME}\n" | uniq')
    if desktop_files_to_packages_command.exit_status == 0
      desktop_packages = desktop_files_to_packages_command.stdout.split("\n")
    else
      desktop_packages = []
    end

    @installed_guis ||= (user_specified_installed_packages + desktop_packages).uniq
  end

  def installed_non_gnome_guis()
    @installed_non_gnome_guis ||= installed_guis - installed_guis.select { |gui| gui.match?(/gnome/) || gui == 'gdm' }
  end

  def has_gui?()
    !installed_guis.empty?
  end

  def has_gnome_gui?()
    installed_guis.any?(/gnome/) || installed_guis.include?('gdm')
  end

  def has_non_gnome_gui?()
    !installed_non_gnome_guis.empty?
  end
end
