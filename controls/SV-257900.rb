control 'SV-257900' do
  title 'RHEL 9 /etc/group- file must be owned by root.'
  desc 'The "/etc/group-" file is a backup file of "/etc/group", and as such, contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify the ownership of the "/etc/group-" file with the following command:

$ sudo stat -c "%U %n" /etc/group- 

root /etc/group- 

If "/etc/group-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/group- to root by running the following command:

$ sudo chown root /etc/group-'
  impact 0.5
  tag check_id: 'C-61641r925685_chk'
  tag severity: 'medium'
  tag gid: 'V-257900'
  tag rid: 'SV-257900r991589_rule'
  tag stig_id: 'RHEL-09-232100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61565r925686_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
