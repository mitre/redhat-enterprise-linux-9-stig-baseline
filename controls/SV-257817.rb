control 'SV-257817' do
  title 'RHEL 9 must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc "ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range. This is enabled by default on the latest Red Hat and Fedora systems if supported by the hardware."
  desc 'check', %q(Verify ExecShield is enabled on 64-bit RHEL 9 systems with the following command:

$ sudo dmesg | grep '[NX|DX]*protection' 

[ 0.000000] NX (Execute Disable) protection: active

If "dmesg" does not show "NX (Execute Disable) protection" active, this is a finding.)
  desc 'fix', 'Update the GRUB 2 bootloader configuration.

Run the following command:

$ sudo grubby --update-kernel=ALL --remove-args=noexec'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61558r925436_chk'
  tag severity: 'medium'
  tag gid: 'V-257817'
  tag rid: 'SV-257817r925438_rule'
  tag stig_id: 'RHEL-09-213110'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-61482r925437_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
