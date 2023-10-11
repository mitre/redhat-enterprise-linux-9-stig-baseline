control 'SV-257942' do
  title 'RHEL 9 must enable hardening for the Berkeley Packet Filter just-in-time compiler.'
  desc 'When hardened, the extended Berkeley Packet Filter (BPF) just-in-time (JIT) compiler will randomize any kernel addresses in the BPF programs and maps, and will not expose the JIT addresses in "/proc/kallsyms".'
  desc 'check', %q(Verify RHEL 9 enables hardening for the BPF JIT with the following commands:

$ sudo sysctl net.core.bpf_jit_harden

net.core.bpf_jit_harden = 2

If the returned line does not have a value of "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.core.bpf_jit_harden | tail -1
net.core.bpf_jit_harden = 2

If the network parameter "net.core.bpf_jit_harden" is not equal to "2" or nothing is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to enable hardening for the BPF JIT compiler by adding the following line to a file, in the "/etc/sysctl.d" directory:

net.core.bpf_jit_harden = 2

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61683r925811_chk'
  tag severity: 'medium'
  tag gid: 'V-257942'
  tag rid: 'SV-257942r925813_rule'
  tag stig_id: 'RHEL-09-251045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61607r925812_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
