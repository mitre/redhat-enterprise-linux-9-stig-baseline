control 'SV-257896' do
  title 'RHEL 9 /etc/passwd- file must have mode 0644 or less permissive to prevent unauthorized access.'
  desc 'The "/etc/passwd-" file is a backup file of "/etc/passwd", and as such, contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify that the "/etc/passwd-" file has mode "0644" or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/passwd-

644 /etc/passwd-

If a value of "0644" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/passwd-" to "0644" by running the following command:

$ sudo chmod 0644 /etc/passwd-'
  impact 0.5
  tag check_id: 'C-61637r925673_chk'
  tag severity: 'medium'
  tag gid: 'V-257896'
  tag rid: 'SV-257896r991589_rule'
  tag stig_id: 'RHEL-09-232080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61561r925674_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
