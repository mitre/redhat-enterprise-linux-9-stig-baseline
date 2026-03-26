control 'SV-257913' do
  title 'RHEL 9 /etc/shadow- file must be group-owned by root.'
  desc 'The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such, contains the list of local system accounts and password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/shadow-" file with the following command:

$ sudo stat -c "%G %n" /etc/shadow-

root /etc/shadow-

If "/etc/shadow-" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /etc/shadow- to root by running the following command:

$ sudo chgrp root /etc/shadow-'
  impact 0.5
  tag check_id: 'C-61654r925724_chk'
  tag severity: 'medium'
  tag gid: 'V-257913'
  tag rid: 'SV-257913r991589_rule'
  tag stig_id: 'RHEL-09-232165'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61578r925725_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
