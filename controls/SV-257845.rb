control 'SV-257845' do
  title 'RHEL 9 must use a separate file system for /var.'
  desc 'Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories installed by other software packages.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var" with the following command:

$ mount | grep /var

UUID=c274f65f-c5b5-4481-b007-bee96feb8b05 /var xfs noatime 1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61586r925520_chk'
  tag severity: 'low'
  tag gid: 'V-257845'
  tag rid: 'SV-257845r925522_rule'
  tag stig_id: 'RHEL-09-231020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61510r925521_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
