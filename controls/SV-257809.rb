control 'SV-257809' do
  title 'RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc "Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code they have introduced into a process' address space during an attempt at exploitation. Additionally, ASLR makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques.

"
  desc 'check', %q(Verify RHEL 9 is implementing ASLR with the following command:

$ sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

Check that the configuration files are present to enable this kernel parameter.
Verify the configuration of the kernel.kptr_restrict kernel parameter with the following command:

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F kernel.randomize_va_space | tail -1

kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2" or is missing, this is a finding.)
  desc 'fix', 'Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.randomize_va_space = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61550r925412_chk'
  tag severity: 'medium'
  tag gid: 'V-257809'
  tag rid: 'SV-257809r925414_rule'
  tag stig_id: 'RHEL-09-213070'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-61474r925413_fix'
  tag satisfies: ['SRG-OS-000433-GPOS-00193', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002824']
  tag nist: ['CM-6 b', 'SI-16']
end
