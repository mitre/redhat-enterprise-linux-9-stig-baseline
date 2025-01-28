control 'SV-257969' do
  title 'RHEL 9 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table possibly revealing portions of the network topology.

The ability to send ICMP redirects is only appropriate for systems acting as routers."
  desc 'check', %q(Verify RHEL 9 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.default.send_redirects | tail -1

net.ipv4.conf.default.send_redirects = 0

If "net.ipv4.conf.default.send_redirects" is not set to "0" and is not documented with the information system security officer (ISSO) as an operational requirement or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257969'
  tag rid: 'SV-257969r942999_rule'
  tag stig_id: 'RHEL-09-253070'
  tag fix_id: 'F-61634r925893_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }
  if input('send_redirects')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  elsif input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    parameter = 'net.ipv4.conf.default.send_redirects'
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
end
