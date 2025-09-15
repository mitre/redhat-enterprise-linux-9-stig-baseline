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

  # TODO: q1: the /usr/share/xsessions directory seems to include .desktop files that display managers use to start a GUI session; however, there is no hardlink between this .desktop file existing and a GUI being installed.  it is possible to start a GUI without having a .desktop file in that location in which case this control would have to apply but we would have marked it as skipped.  what would be the process for actually identifying that no gui was installed?  do we just check for gnome packages in particular being installed since that's what the checktext describes?  and if a non-gnome package is installed then we have to fall back to manual review as the requirement is still applicable?  maybe we have to use an input where we force the user to tell us what desktop environment/gui that they're using?  what if they have multiple DE's installed and these rules are in place for gnome but not for the other DE's so someone could still violate the requirements specified in other controls?
  # TODO: after further research and discussion, it's this and/or look at the list of all packages installed and see if any of them match desktop environments but that's gonna be having problems cause you can install whatever DE you want beyond just the standards, and even then there's no comprehensive list of standards beyond like gnome, kde, cinnamon, xfce, and for kde especially you will get false positives.  one possible approach that we could do is make the user supply an input of stuff that's installed with a default of whatever DEs we can think of and identify if any of those packages are installed.  alongside that, we look in this directory for anything.  if we get no results whatsoever, we get to do the NA out cause no GUIs were installed.  if we get any that are non-gnome, then we have to do the manual review.  if we get gnome, then we actually are able to do the below test as per the checktext.
  if !gui.has_gui?
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  else
    if !gui.has_gnome_gui?
      describe 'Non-gnome desktop environments detected' do
        skip 'Manual check required.  There is no guidance for non-gnome desktop environments.'
      end
    end

    if gui.has_gnome_gui?
      # TODO: q2: should we make a dconf resource?
      db_list = command('find /etc/dconf/db -maxdepth 1 -type f').stdout.strip.split("\n")

      # TODO: q3: is there always a db.d for every db?  I feel like the answer might be no which is what is leading to a `comparison of Integer with nil failed` error
      # TODO: q4: the checktext compares the contents of each of those dbs not to the db.d directory itself but to the oldest mtime of those directory contents.  the contents themselves include user defined rules in file(s) named in a ##-name format and then a 'locks' directory that could contain file(s) that seem to share the same naming scheme.  there definitely are not always user defined rules files.  is there always going to be a locks directory in there or is it possible that db.d could be empty entirely?
      # TODO: q5: why does the checktext check if the values are numbers before doing the comparison?  is it just defensive programming or is there actually a chance that those stats will not succeed for some reason?
      failing_dbs = db_list.select { |db| file(db).mtime < file("#{db}.d").mtime }

      describe 'dconf databases' do
        it 'should have been updated after the last corresponding keyfile edit' do
          expect(failing_dbs).to be_empty, "Failing databases:\n\t- #{failing_dbs.join("\n\t- ")}"
        end
      end
    end
  end
end
