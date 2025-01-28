control 'SV-257977' do
  title 'RHEL 9 must not forward IPv6 source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

Accepting source-routed packets in the IPv6 protocol has few legitimate uses. It must be disabled unless it is absolutely required.'
  desc 'check', %q(Verify RHEL 9 does not accept IPv6 source-routed packets by default.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_source_route

net.ipv6.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F net.ipv6.conf.default.accept_source_route | tail -1

net.ipv6.conf.default.accept_source_route = 0

If "net.ipv6.conf.default.accept_source_route" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not forward IPv6 source-routed packets by default.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_source_route = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257977'
  tag rid: 'SV-257977r943011_rule'
  tag stig_id: 'RHEL-09-254040'
  tag fix_id: 'F-61642r925917_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'net.ipv6.conf.default.accept_source_route'
  value = 0
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv6_enabled') == false
    impact 0.0
    describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
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
