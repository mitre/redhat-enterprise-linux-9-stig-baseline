control 'SV-257970' do
  title 'RHEL 9 must not enable IPv4 packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this capability is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', %q(Verify RHEL 9 is not performing IPv4 packet forwarding unless the system is a router.

Check that IPv4 forwarding is disabled using the following command:

$ sudo sysctl net.ipv4.conf.all.forwarding

net.ipv4.conf.all.forwarding = 0

If the IPv4 forwarding value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|$)' | grep -F net.ipv4.conf.all.forwarding | tail -1

net.ipv4.conf.all.forwarding = 0

If "net.ipv4.conf.all.forwarding" is not set to "0" and is not documented with the ISSO as an operational requirement or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not allow IPv4 packet forwarding, unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.forwarding = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-61711r1045010_chk'
  tag severity: 'medium'
  tag gid: 'V-257970'
  tag rid: 'SV-257970r1045011_rule'
  tag stig_id: 'RHEL-09-253075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61635r925896_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  if input('packet_forwarding_enabled')
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

    parameter = 'net.ipv4.conf.all.forwarding'
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
