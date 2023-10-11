control 'SV-257788' do
  title 'RHEL 9 must disable the ability of systemd to spawn an interactive boot process.'
  desc 'Using interactive or recovery boot, the console user could disable auditing, firewalls, or other services, weakening system security.'
  desc 'check', "Verify that GRUB 2 is configured to disable interactive boot.

Check that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'

If any output is returned, this is a finding."
  desc 'fix', 'Configure RHEL 9 to allocate sufficient audit_backlog_limit to disable the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61529r925349_chk'
  tag severity: 'medium'
  tag gid: 'V-257788'
  tag rid: 'SV-257788r925351_rule'
  tag stig_id: 'RHEL-09-212015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61453r925350_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
