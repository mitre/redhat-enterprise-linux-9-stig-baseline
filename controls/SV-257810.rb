control 'SV-257810' do
  title 'RHEL 9 must disable access to network bpf system call from nonprivileged processes.'
  desc 'Loading and accessing the packet filters programs and maps using the bpf() system call has the potential of revealing sensitive information about the kernel state.

'
  desc 'check', %q(Verify RHEL 9 prevents privilege escalation thru the kernel by disabling access to the bpf system call with the following commands:

$ sysctl kernel.unprivileged_bpf_disabled

kernel.unprivileged_bpf_disabled = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.unprivileged_bpf_disabled | tail -1
kernel.unprivileged_bpf_disabled = 1

If the network parameter "ipv4.tcp_syncookies" is not equal to "1", or nothing is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to prevent privilege escalation thru the kernel by disabling access to the bpf syscall by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.unprivileged_bpf_disabled = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61551r925415_chk'
  tag severity: 'medium'
  tag gid: 'V-257810'
  tag rid: 'SV-257810r925417_rule'
  tag stig_id: 'RHEL-09-213075'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61475r925416_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
end
