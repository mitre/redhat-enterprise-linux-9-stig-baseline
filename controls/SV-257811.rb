control 'SV-257811' do
  title 'RHEL 9 must restrict usage of ptrace to descendant processes.'
  desc 'Unrestricted usage of ptrace allows compromised binaries to run ptrace on other processes of the user. Like this, the attacker can steal sensitive information from the target processes (e.g., SSH sessions, web browser, etc.) without any additional assistance from the user (i.e., without resorting to phishing).'
  desc 'check', %q(Verify RHEL 9 restricts the usage of ptrace to descendant processes with the following commands:

$ sysctl kernel.yama.ptrace_scope

kernel.yama.ptrace_scope = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.yama.ptrace_scope| tail -1

kernel.yama.ptrace_scope = 1

If the network parameter "kernel.yama.ptrace_scope" is not equal to "1", or nothing is returned, this is a finding.)
  desc 'fix', 'Configure the currently loaded kernel parameter to the secure setting:

$ sudo sysctl -w kernel.yama.ptrace_scope=1

Configure RHEL 9 to restrict usage of ptrace to descendant processes by adding the following line to a file in the "/etc/sysctl.d" directory:

kernel.yama.ptrace_scope = 1

The system configuration files must be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sysctl --system'
  impact 0.5
  tag check_id: 'C-61552r1044870_chk'
  tag severity: 'medium'
  tag gid: 'V-257811'
  tag rid: 'SV-257811r1044872_rule'
  tag stig_id: 'RHEL-09-213080'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61476r1044871_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.yama.ptrace_scope'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

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
