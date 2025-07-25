control 'SV-257963' do
  title 'RHEL 9 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

This feature of the IPv4 protocol has few legitimate uses. It must be disabled unless absolutely required."
  desc 'check', %q(Verify RHEL 9 will not accept IPv4 ICMP redirect messages.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_redirects

net.ipv4.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.default.accept_redirects | tail -1

net.ipv4.conf.default.accept_redirects = 0

If "net.ipv4.conf.default.accept_redirects" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to prevent IPv4 ICMP redirect messages from being accepted.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.accept_redirects = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257963'
  tag rid: 'SV-257963r991589_rule'
  tag stig_id: 'RHEL-09-253040'
  tag fix_id: 'F-61628r925875_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'net.ipv4.conf.default.accept_redirects'
  value = 0
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
