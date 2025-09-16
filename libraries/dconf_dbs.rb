require 'inspec/utils/filter'

class DConfDBs < Inspec.resource(1)
  name 'dconf_dbs'

  supports platform: 'redhat', release: '9.*'

  ft = FilterTable.create

  ft.register_column(:name, field: :name)
  ft.register_column(:mtime, field: :mtime)
  ft.register_column(:keyfile_dir, field: :keyfile_dir)
  ft.register_column(:keyfile_dir_exists, field: :keyfile_dir_exists)

  ft.register_custom_matcher(:has_keyfiles_dir?) { |table| table.keyfile_dir_exists.all? }
  # matcher for the mtime comparison

  ft.install_filter_methods_on_resource(self, :collect_dconf_dbs_details)

  def to_s
    'dconf databases'
  end

  private

  def collect_dconf_dbs_details
    dbs = inspec.command('find /etc/dconf/db -maxdepth 1 -type f').stdout.strip.split("\n")
    dbs.map { |db| { name: db, mtime: inspec.file(db).mtime, keyfile_dir: "#{db}.d/", keyfile_dir_exists:  inspec.file("#{db}.d/").exist? } } # add in keyfiles + lock files
  end
end
