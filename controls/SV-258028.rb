control 'SV-258028' do
  title 'RHEL 9 effective dconf policy must match the policy keyfiles.'
  desc 'Unlike text-based keyfiles, the binary database is impossible to check through most automated and all manual means; therefore, in order to evaluate dconf configuration, both have to be true at the same time - configuration files have to be compliant, and the database needs to be more recent than those keyfiles, which gives confidence that it reflects them.'
  desc 'check', 'Check the last modification time of the local databases, comparing it to the last modification time of the related keyfiles. The following command will check every dconf database and compare its modification time to the related system keyfiles:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ function dconf_needs_update { for db in $(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=$(stat -c %Y "$db"); keyfile_mtime=$(stat -c %Y "$db".d/* | sort -n | tail -1); if [ -n "$db_mtime" ] && [ -n "$keyfile_mtime" ] && [ "$db_mtime" -lt "$keyfile_mtime" ]; then echo "$db needs update"; return 1; fi; done; }; dconf_needs_update

If the command has any output, then a dconf database needs to be updated, and this is a finding.'
  desc 'fix', 'Update the dconf databases by running the following command:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61769r926069_chk'
  tag severity: 'medium'
  tag gid: 'V-258028'
  tag rid: 'SV-258028r991589_rule'
  tag stig_id: 'RHEL-09-271090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61693r926070_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))

  if g.has_gui?
    if g.has_gnome_gui?
      describe "Each dconf database" do
        subject { dconf_dbs }
        it "is expected to have a keyfiles directory." do
          failure_message = "These dconf databases do not have keyfiles directories:\n\t- #{dconf_dbs.where(keyfile_dir_exists: false).name.join("\n\t- ")}"
          expect(subject).to have_keyfiles_dir, failure_message
        end
      end

      # TODO: q2: should we make a dconf resource?
      db_list = command('find /etc/dconf/db -maxdepth 1 -type f').stdout.strip.split("\n")

      # TODO: q3: is there always a db.d for every db?  I feel like the answer might be no which is what is leading to a `comparison of Integer with nil failed` error
      # local testing by deleting one of the .d dirs is the only way I've been able to replicate that error, but still need to validate by looking at the original system that caused this error
      # TODO: q4: the checktext compares the contents of each of those dbs not to the db.d directory itself but to the oldest mtime of those directory contents.  the contents themselves include user defined rules in file(s) named in a ##-name format and then a 'locks' directory that could contain file(s) that seem to share the same naming scheme.  there definitely are not always user defined rules files.  is there always going to be a locks directory in there or is it possible that db.d could be empty entirely?
      # there doesn't seem to be a guarantee that a locks dir is always there
      # was able to confirm that our logic marks a fail with the .d dir is touched but the checktext script passes it whereas the script causes a fail when the rules inside are touched but our code passes it which confirms my thoughts that our implementation is bugged due to mistakenly thinking that the mtime of a dir is influenced by mtime updates to items inside the dir
      # i think that the provided script is also wrong though cause it falls into that same fallacy of mtime of a dir actually means anything cause we should actually be checking the mtimes of the "FILE"s inside of the .d and .d/locks dirs not the mtimes of all files (and dirs) inside of the .d
      # TODO: q5: why does the checktext check if the values are numbers before doing the comparison?  is it just defensive programming or is there actually a chance that those stats will not succeed for some reason?
      # presumably there is a chance that those commands will not succeed considering the above research showing that the .d directory might not exist, but then again that command failed when that .d dir was not there so still not sure if the author was expecting that case to exist
      failing_dbs = db_list.select { |db| !file("#{db}.d").exist? || file(db).mtime < file("#{db}.d").mtime }

      if g.has_non_gnome_gui?
        unless failing_dbs.empty?
          describe 'dconf databases' do
            it 'should have been updated after the last corresponding keyfile edit' do
              expect(failing_dbs).to be_empty, "Failing databases:\n\t- #{failing_dbs.join("\n\t- ")}"
            end
          end
        end
        describe 'Non-GNOME desktop environments detected' do
          skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
        end
      else
        describe 'dconf databases' do
          it 'should have been updated after the last corresponding keyfile edit' do
            expect(failing_dbs).to be_empty, "Failing databases:\n\t- #{failing_dbs.join("\n\t- ")}"
          end
        end
      end
    else
      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_guis.join("\n\t- ")}"
      end
    end
  else
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  end
end
