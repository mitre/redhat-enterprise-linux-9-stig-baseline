control 'SV-257801' do
  title 'RHEL 9 must enable kernel parameters to enforce discretionary access control on hardlinks.'
  desc 'By enabling the fs.protected_hardlinks kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigates vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().'
  desc 'check', %q(Verify RHEL 9 is configured to enable DAC on hardlinks.

Check the status of the fs.protected_hardlinks kernel parameter with the following command:

$ sudo sysctl fs.protected_hardlinks

fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F fs.protected_hardlinks | tail -1

fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to enable DAC on hardlinks with the following:

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

fs.protected_hardlinks = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000312-GPOS-00123'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124', 'SRG-OS-000324-GPOS-00125']
  tag gid: 'V-257801'
  tag rid: 'SV-257801r925390_rule'
  tag stig_id: 'RHEL-09-213030'
  tag fix_id: 'F-61466r925389_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'fs.protected_hardlinks'
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
