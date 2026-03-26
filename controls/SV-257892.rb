control 'SV-257892' do
  title 'RHEL 9 /etc/group- file must have mode 0644 or less permissive to prevent unauthorized access.'
  desc 'The "/etc/group-" file is a backup file of "/etc/group", and as such, contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify that the "/etc/group-" file has mode "0644" or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/group-

644 /etc/group-

If a value of "0644" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/group-" to "0644" by running the following command:

$ sudo chmod 0644 /etc/group-'
  impact 0.5
  tag check_id: 'C-61633r925661_chk'
  tag severity: 'medium'
  tag gid: 'V-257892'
  tag rid: 'SV-257892r991589_rule'
  tag stig_id: 'RHEL-09-232060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61557r925662_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
