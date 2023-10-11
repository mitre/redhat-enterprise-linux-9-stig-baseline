control 'SV-257800' do
  title 'RHEL 9 must restrict exposed kernel pointer addresses access.'
  desc 'Exposing kernel pointers (through procfs or "seq_printf()") exposes kernel writeable structures, which may contain functions pointers. If a write vulnerability occurs in the kernel, allowing write access to any of this structure, the kernel can be compromised. This option disallows any program without the CAP_SYSLOG capability to get the addresses of kernel pointers by replacing them with "0".

'
  desc 'check', %q(Verify the runtime status of the kernel.kptr_restrict kernel parameter with the following command:

$ sysctl kernel.kptr_restrict 

kernel.kptr_restrict = 1

Verify the configuration of the kernel.kptr_restrict kernel parameter with the following command:

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F kernel.kptr_restrict | tail -1

kernel.kptr_restrict =1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61541r925385_chk'
  tag severity: 'medium'
  tag gid: 'V-257800'
  tag rid: 'SV-257800r925387_rule'
  tag stig_id: 'RHEL-09-213025'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61465r925386_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000433-GPOS-00192', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082', 'CCI-002824']
  tag nist: ['CM-6 b', 'SC-2', 'SI-16']
end
