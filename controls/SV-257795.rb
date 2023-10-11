control 'SV-257795' do
  title 'RHEL 9 must enable mitigations against processor-based vulnerabilities.'
  desc 'Kernel page-table isolation is a kernel feature that mitigates the Meltdown security vulnerability and hardens the kernel against attempts to bypass kernel address space layout randomization (KASLR).

'
  desc 'check', 'Verify RHEL 9 enables kernel page-table isolation with the following command:

$ sudo grubby --info=ALL | grep pti

args="ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 pti=on 

If the "pti" entry does not equal "on", or is missing, this is a finding.

Check that kernel page-table isolation is enabled by default to persist in kernel updates: 

$ sudo grep pti /etc/default/grub

GRUB_CMDLINE_LINUX="pti=on"

If "pti" is not set to "on", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enable kernel page-table isolation with the following command:

$ sudo grubby --update-kernel=ALL --args="pti=on"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="pti=on"'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61536r925370_chk'
  tag severity: 'low'
  tag gid: 'V-257795'
  tag rid: 'SV-257795r925372_rule'
  tag stig_id: 'RHEL-09-212050'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-61460r925371_fix'
  tag satisfies: ['SRG-OS-000433-GPOS-00193', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-002824']
  tag nist: ['CM-7 a', 'SI-16']
end
