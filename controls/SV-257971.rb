control 'SV-257971' do
  title 'RHEL 9 must not accept router advertisements on all IPv6 interfaces.'
  desc 'An illicit router advertisement message could result in a man-in-the-middle attack.'
  desc 'check', %q(Verify RHEL 9 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Determine if router advertisements are not accepted by using the following command:

$ sudo sysctl net.ipv6.conf.all.accept_ra

net.ipv6.conf.all.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv6.conf.all.accept_ra | tail -1

net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not accept router advertisements on all IPv6 interfaces unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_ra = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257971'
  tag rid: 'SV-257971r991589_rule'
  tag stig_id: 'RHEL-09-254010'
  tag fix_id: 'F-61636r925899_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('accept_ra_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    parameter = 'net.ipv6.conf.all.accept_ra'
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
