control 'SV-257793' do
  title 'RHEL 8 must clear the page allocator to prevent use-after-free
attacks.'
  desc 'Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Poisoning writes an arbitrary value to freed pages, so any modification or
reference to that page after being freed or before being initialized will be
detected and prevented. This prevents many types of use-after-free
vulnerabilities at little performance cost. Also prevents leak of data and
detection of corrupted memory.'
  desc 'check', 'Verify that GRUB 2 is configured to enable page poisoning to mitigate use-after-free vulnerabilities with the following commands:

Check that the current GRUB 2 configuration has page poisoning enabled:

$ sudo grub2-editenv list | grep page_poison

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If "page_poison" is not set to "1" or is missing, this is a finding.

Check that page poisoning is enabled by default to persist in kernel updates:

$ sudo grep page_poison /etc/default/grub

GRUB_CMDLINE_LINUX="page_poison=1"

If "page_poison" is not set to "1", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enable page poisoning with the following commands:

    $ sudo grubby --update-kernel=ALL --args="page_poison=1"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="page_poison=1"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192']
  tag gid: 'V-230277'
  tag rid: 'SV-257793r792884_rule'
  tag stig_id: 'RHEL-08-010421'
  tag fix_id: 'F-32921r567578_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host'

  grub_stdout = command('grub2-editenv - list').stdout
  setting = /page_poison\s*=\s*1/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['kernelopts']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
