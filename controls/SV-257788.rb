control 'SV-257788' do
  title 'RHEL 9 must disable the ability of systemd to spawn an interactive boot process.'
  desc 'Using interactive or recovery boot, the console user could disable auditing, firewalls, or other services, weakening system security.'
  desc 'check', "Verify that GRUB 2 is configured to disable interactive boot.

Check that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'

If any output is returned, this is a finding."
  desc 'fix', 'Configure the current GRUB 2 configuration to disable the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"'
  impact 0.5
  tag check_id: 'C-61529r925349_chk'
  tag severity: 'medium'
  tag gid: 'V-257788'
  tag rid: 'SV-257788r1044838_rule'
  tag stig_id: 'RHEL-09-212015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61453r1044837_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  grubby = command('grubby --info=ALL').stdout

  describe parse_config(grubby) do
    its('args') { should_not include 'systemd.confirm_spawn' }
  end
end
