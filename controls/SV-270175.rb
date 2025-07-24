control 'SV-270175' do
  title 'RHEL 9 "/etc/audit/" must be owned by root.'
  desc 'The "/etc/audit/" directory contains files that ensure the proper auditing of command execution, privilege escalation, file manipulation, and more. Protection of this directory is critical for system security.'
  desc 'check', 'Verify the ownership of the "/etc/audit/" directory with the following command:

$ sudo stat -c "%U %n" /etc/audit/

root /etc/audit/

If the "/etc/audit/" directory does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file "/etc/audit/" to "root" by running the following command:

$ sudo chown root /etc/audit/'
  impact 0.5
  tag check_id: 'C-74208r1044962_chk'
  tag severity: 'medium'
  tag gid: 'V-270175'
  tag rid: 'SV-270175r1044964_rule'
  tag stig_id: 'RHEL-09-232103'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-74109r1044963_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']

  describe file('/etc/audit/') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
