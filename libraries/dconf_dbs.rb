require 'inspec/utils/filter'

class DConfDBs < Inspec.resource(1)
  name 'dconf_dbs'

  supports platform: 'redhat', release: '9.*'

  ft = FilterTable.create

  ft.register_column(:name, field: :name)
  ft.register_column(:mtime, field: :mtime)
  ft.register_column(:keyfile_dir, field: :keyfile_dir)
  ft.register_column(:keyfile_dir_exists, field: :keyfile_dir_exists)
  ft.register_column(:keyfiles, field: :keyfiles)
  ft.register_column(:lockfiles, field: :lockfiles)

  ft.register_custom_matcher(:has_keyfiles_dir?) { |table| table.keyfile_dir_exists.all? }
  ft.register_custom_matcher(:has_latest_keyfiles_dir_updates?) { |table| table.where { !keyfiles.empty? && keyfiles.all? { |kf| mtime < kf[:mtime] } }.count == 0 }
  ft.register_custom_matcher(:has_latest_lockfiles_dir_updates?) { |table| table.where { !lockfiles.empty? && lockfiles.all? { |lf| mtime < lf[:mtime] } }.count == 0 }

  ft.install_filter_methods_on_resource(self, :collect_dconf_dbs_details)

  def to_s
    'dconf databases'
  end

  private

  def collect_dconf_dbs_details
    dbs = inspec.command('find /etc/dconf/db/ -maxdepth 1 -type f').stdout.strip.split("\n")
    dbs.map { |db|
      keyfile_dir_exists = inspec.file("#{db}.d/").exist?
      keyfiles = keyfile_dir_exists ? inspec.command("find -L #{db}.d/ -maxdepth 1 -type f").stdout.strip.split("\n").map { |f| { name: f, mtime: inspec.file(f).mtime } } : []
      lockfiles = keyfile_dir_exists && inspec.file("#{db}.d/locks").exist? ? inspec.command("find -L #{db}.d/locks -maxdepth 1 -type f").stdout.strip.split("\n").map { |f| { name: f, mtime: inspec.file(f).mtime } } : []
      {
        name: db,
        mtime: inspec.file(db).mtime,
        keyfile_dir: "#{db}.d/",
        keyfile_dir_exists: keyfile_dir_exists,
        keyfiles: keyfiles,
        lockfiles: lockfiles
      }
    }
  end
end
