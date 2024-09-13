control 'SV-257957' do
  title 'RHEL 9 must be configured to use TCP syncookies.'
  desc 'Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', %q(Verify RHEL 9 is configured to use IPv4 TCP syncookies.

Determine if syncookies are used with the following command:

Check the status of the kernel.perf_event_paranoid kernel parameter.

$ sudo sysctl net.ipv4.tcp_syncookies

net.ipv4.tcp_syncookies = 1

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.tcp_syncookies | tail -1

net.ipv4.tcp_syncookies = 1

If the network parameter "ipv4.tcp_syncookies" is not equal to "1" or nothing is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to use TCP syncookies.

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:
 net.ipv4.tcp_syncookies = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61698r942982_chk'
  tag severity: 'medium'
  tag gid: 'V-257957'
  tag rid: 'SV-257957r991589_rule'
  tag stig_id: 'RHEL-09-253010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61622r925857_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00071']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001095', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 (2)', 'SC-5 a']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'net.ipv4.tcp_syncookies'
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
