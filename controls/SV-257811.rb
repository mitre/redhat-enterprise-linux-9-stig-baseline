control 'SV-257811' do
  title 'RHEL 9 must restrict usage of ptrace to descendant processes.'
  desc 'Unrestricted usage of ptrace allows compromised binaries to run ptrace on other processes of the user. Like this, the attacker can steal sensitive information from the target processes (e.g., SSH sessions, web browser, etc.) without any additional assistance from the user (i.e., without resorting to phishing).

'
  desc 'check', %q(Verify RHEL 9 restricts usage of ptrace to descendant processes with the following commands:

$ sysctl kernel.yama.ptrace_scope

kernel.yama.ptrace_scope = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.yama.ptrace_scope| tail -1
kernel.yama.ptrace_scope = 1

If the network parameter "kernel.yama.ptrace_scope" is not equal to "1", or nothing is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to restrict usage of ptrace to descendant processes by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.yama.ptrace_scope = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61552r925418_chk'
  tag severity: 'medium'
  tag gid: 'V-257811'
  tag rid: 'SV-257811r925420_rule'
  tag stig_id: 'RHEL-09-213080'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61476r925419_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
end
