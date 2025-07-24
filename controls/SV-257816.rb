control 'SV-257816' do
  title 'RHEL 9 must disable the use of user namespaces.'
  desc 'User namespaces are used primarily for Linux containers. The value "0" disallows the use of user namespaces.'
  desc 'check', %q(Verify RHEL 9 disables the use of user namespaces with the following commands:

$ sudo sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F user.max_user_namespaces | tail -1
user.max_user_namespaces = 0

If the network parameter "user.max_user_namespaces" is not equal to "0", or nothing is returned, this is a finding.

If the use of namespaces is operationally required and documented with the information system security manager (ISSM), this is not a finding.)
  desc 'fix', 'Configure RHEL 9 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

user.max_user_namespaces = 0

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257816'
  tag rid: 'SV-257816r1014825_rule'
  tag stig_id: 'RHEL-09-213105'
  tag fix_id: 'F-61481r1014824_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'user.max_user_namespaces'
  value = 0
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
