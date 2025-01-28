control 'SV-257810' do
  title 'RHEL 9 must disable access to network bpf system call from nonprivileged processes.'
  desc 'Loading and accessing the packet filters programs and maps using the bpf() system call has the potential of revealing sensitive information about the kernel state.'
  desc 'check', %q(Verify RHEL 9 prevents privilege escalation thru the kernel by disabling access to the bpf system call with the following commands:

$ sudo sysctl kernel.unprivileged_bpf_disabled

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
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-257810'
  tag rid: 'SV-257810r942977_rule'
  tag stig_id: 'RHEL-09-213075'
  tag fix_id: 'F-61475r925416_fix'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.unprivileged_bpf_disabled'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else
    describe kernel_parameter(parameter) do
      its('value') { should eq value }
    end

    search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

    correct_result = search_results.any? { |line| line.match(regexp) }
    incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

    describe 'Kernel config files' do
      it "should configure '#{parameter}'" do
        expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
      end
      unless incorrect_results.nil?
        it 'should not have incorrect or conflicting setting(s) in the config files' do
          expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
        end
      end
    end
  end
end
