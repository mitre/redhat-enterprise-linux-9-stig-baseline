control 'SV-257843' do
  title 'A separate RHEL 9 file system must be used for user home directories (such as /home or an equivalent).'
  desc 'Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/home" with the following command:

$ mount | grep /home

UUID=fba5000f-2ffa-4417-90eb-8c54ae74a32f on /home type ext4 (rw,nodev,nosuid,noexec,seclabel)

If a separate entry for "/home" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/home" directory onto a separate file system/partition.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61584r925514_chk'
  tag severity: 'medium'
  tag gid: 'V-257843'
  tag rid: 'SV-257843r925516_rule'
  tag stig_id: 'RHEL-09-231010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61508r925515_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
