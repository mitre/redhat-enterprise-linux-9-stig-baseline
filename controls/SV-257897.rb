control 'SV-257897' do
  title 'RHEL 9 /etc/shadow- file must have mode 0000 or less permissive to prevent unauthorized access.'
  desc 'The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such, contains the list of local system accounts and password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify that the "/etc/shadow-" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/shadow-

0 /etc/shadow-

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/shadow-" to "0000" by running the following command:

$ sudo chmod 0000 /etc/shadow-'
  impact 0.5
  tag check_id: 'C-61638r925676_chk'
  tag severity: 'medium'
  tag gid: 'V-257897'
  tag rid: 'SV-257897r991589_rule'
  tag stig_id: 'RHEL-09-232085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61562r925677_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
