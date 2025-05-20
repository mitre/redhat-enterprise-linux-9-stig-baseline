control 'SV-270176' do
  title 'RHEL 9 "/etc/audit/" must be group-owned by root.'
  desc 'The "/etc/audit/" directory contains files that ensure the proper auditing of command execution, privilege escalation, file manipulation, and more. Protection of this directory is critical for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/audit/" directory with the following command:

$ sudo stat -c "%G %n" /etc/audit/

root /etc/audit/

If "/etc/audit/" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file "/etc/audit/" to "root" by running the following command:

$ sudo chgrp root /etc/audit/'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-74209r1044965_chk'
  tag severity: 'medium'
  tag gid: 'V-270176'
  tag rid: 'SV-270176r1044967_rule'
  tag stig_id: 'RHEL-09-232104'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-74110r1044966_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']

  describe file('/etc/audit/') do
    it { should exist }
    its('group') { should cmp 'root' }
  end
end