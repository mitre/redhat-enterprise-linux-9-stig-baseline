control 'SV-257912' do
  title 'RHEL 9 /etc/shadow- file must be owned by root.'
  desc 'The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such, contains the list of local system accounts and password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify the ownership of the "/etc/shadow-" file with the following command:

$ sudo stat -c "%U %n" /etc/shadow- 

root /etc/shadow- 

If "/etc/shadow-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/shadow- to root by running the following command:

$ sudo chown root /etc/shadow-'
  impact 0.5
  tag check_id: 'C-61653r925721_chk'
  tag severity: 'medium'
  tag gid: 'V-257912'
  tag rid: 'SV-257912r991589_rule'
  tag stig_id: 'RHEL-09-232160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61577r925722_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
