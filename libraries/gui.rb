class Gui < Inspec.resource(1)
  name 'gui'

  supports platform: 'redhat', release: '9.*'

  def installed_guis()
    user_specified_packages = input('possibly_installed_guis')
    user_specified_installed_packages = user_specified_packages.select do |package|
      inspec.package(package).installed?
    end

    desktop_files_to_packages_command = inspec.command('ls -w 1 /usr/share/xsessions/ | xargs -I{} rpm -qf /usr/share/xsessions/{} --qf "%{NAME}\n" | uniq')
    if desktop_files_to_packages_command.exit_status != 0
      desktop_packages = desktop_files_to_packages_command.stdout.split("\n")
    else
      desktop_packages = []
    end

    @installed_guis ||= (user_specified_installed_packages + desktop_packages).uniq
  end

  def installed_non_gnome_guis()
    @installed_non_gnome_guis ||= installed_guis - installed_guis.all?(/gnome/)
  end

  def has_gui?()
    !installed_guis.empty?
  end

  def has_gnome_gui?()
    installed_guis.any?(/gnome/)
  end

  def has_non_gnome_gui?()
    installed_non_gnome_guis.empty?
  end
end
