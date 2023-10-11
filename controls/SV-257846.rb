control 'SV-257846' do
  title 'RHEL 9 must use a separate file system for /var/log.'
  desc 'Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var/log" with the following command:

$ mount | grep /var/log

UUID=c274f65f-c5b5-4486-b021-bee96feb8b21 /var/log xfs noatime 1 2

If a separate entry for "/var/log" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/log" path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61587r925523_chk'
  tag severity: 'low'
  tag gid: 'V-257846'
  tag rid: 'SV-257846r925525_rule'
  tag stig_id: 'RHEL-09-231025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61511r925524_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
