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
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61769r926069_chk'
  tag severity: 'medium'
  tag gid: 'V-258028'
  tag rid: 'SV-258028r926071_rule'
  tag stig_id: 'RHEL-09-271090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61693r926070_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
