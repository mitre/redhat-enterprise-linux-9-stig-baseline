control 'SV-257793' do
  title 'RHEL 9 must clear the page allocator to prevent use-after-free attacks.'
  desc 'Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.

'
  desc 'check', %q(Verify that GRUB 2 is configured to enable page poisoning to mitigate use-after-free vulnerabilities.

Check that the current GRUB 2 configuration has page poisoning enabled  with the following command:

$ sudo grubby --info=ALL | grep args | grep -v 'page_poison=1'

If any output is returned, this is a finding.

Check that page poisoning is enabled by default to persist in kernel updates with the following command: 

$ sudo grep page_poison /etc/default/grub

GRUB_CMDLINE_LINUX="page_poison=1"

If "page_poison" is not set to "1", is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to enable page poisoning with the following commands:

$ sudo grubby --update-kernel=ALL --args="page_poison=1"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="page_poison=1"'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61534r925364_chk'
  tag severity: 'medium'
  tag gid: 'V-257793'
  tag rid: 'SV-257793r925366_rule'
  tag stig_id: 'RHEL-09-212040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61458r925365_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000134-GPOS-00068']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001084']
  tag nist: ['CM-6 b', 'SC-3']
end
