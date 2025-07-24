control 'SV-257967' do
  title 'RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.'
  desc 'Some routers will send responses to broadcast frames that violate RFC-1122, which fills up a log file system with many useless error messages. An attacker may take advantage of this and attempt to flood the logs with bogus error logs. Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.'
  desc 'check', %q(The runtime status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter can be queried by running the following command:

$ sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses

net.ipv4.icmp_ignore_bogus_error_responses = 1

If "net.ipv4.icmp_ignore_bogus_error_responses" is not set to "1", this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.icmp_ignore_bogus_error_response | tail -1

net.ipv4.icmp_ignore_bogus_error_response = 1

If "net.ipv4.icmp_ignore_bogus_error_response" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not log bogus ICMP errors:

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.icmp_ignore_bogus_error_responses = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-61708r925886_chk'
  tag severity: 'medium'
  tag gid: 'V-257967'
  tag rid: 'SV-257967r991589_rule'
  tag stig_id: 'RHEL-09-253060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61632r925887_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'net.ipv4.icmp_ignore_bogus_error_responses'
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
