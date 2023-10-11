control 'SV-257794' do
  title 'RHEL 9 must clear SLUB/SLAB objects to prevent use-after-free attacks.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.

SLAB objects are blocks of physically contiguous memory. SLUB is the unqueued SLAB allocator.

'
  desc 'check', %q(Verify that GRUB 2 is configured to enable poisoning of SLUB/SLAB objects to mitigate use-after-free vulnerabilities with the following commands:

Check that the current GRUB 2 configuration has poisoning of SLUB/SLAB objects enabled:

$ sudo grubby --info=ALL | grep args | grep -v 'slub_debug=P' 

If any output is returned, this is a finding.

Check that poisoning of SLUB/SLAB objects is enabled by default to persist in kernel updates: 

$ sudo grep slub_debug /etc/default/grub

GRUB_CMDLINE_LINUX="slub_debug=P"

If "slub_debug" is not set to "P", is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL  to enable poisoning of SLUB/SLAB objects with the following commands:

$ sudo grubby --update-kernel=ALL --args="slub_debug=P"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="slub_debug=P"'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61535r925367_chk'
  tag severity: 'medium'
  tag gid: 'V-257794'
  tag rid: 'SV-257794r925369_rule'
  tag stig_id: 'RHEL-09-212045'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-61459r925368_fix'
  tag satisfies: ['SRG-OS-000433-GPOS-00192', 'SRG-OS-000134-GPOS-00068']
  tag 'documentable'
  tag cci: ['CCI-001084', 'CCI-002824']
  tag nist: ['SC-3', 'SI-16']
end
