control 'SV-257908' do
  title 'RHEL 9 /etc/passwd- file must be owned by root.'
  desc 'The "/etc/passwd-" file is a backup file of "/etc/passwd", and as such, contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify the ownership of the "/etc/passwd-" file with the following command:

$ sudo stat -c "%U %n" /etc/passwd- 

root /etc/passwd- 

If "/etc/passwd-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/passwd- to root by running the following command:

$ sudo chown root /etc/passwd-'
  impact 0.5
  tag check_id: 'C-61649r925709_chk'
  tag severity: 'medium'
  tag gid: 'V-257908'
  tag rid: 'SV-257908r991589_rule'
  tag stig_id: 'RHEL-09-232140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61573r925710_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
