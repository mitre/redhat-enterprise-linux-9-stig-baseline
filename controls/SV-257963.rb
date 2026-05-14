control 'SV-257963' do
  title 'RHEL 9 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

This feature of the IPv4 protocol has few legitimate uses. It must be disabled unless absolutely required.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf"
  desc 'check', 'Verify RHEL 9 will not accept IPv4 ICMP redirect messages.

Check the value of the default "accept_redirects" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_redirects
net.ipv4.conf.default.accept_redirects = 0

If "net.ipv4.conf.default.accept_redirects" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent IPv4 ICMP redirect messages from being accepted.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_accept_redirects.conf

Add the following line to the file:
net.ipv4.conf.default.accept_redirects = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257963'
  tag rid: 'SV-257963r1155736_rule'
  tag stig_id: 'RHEL-09-253040'
  tag fix_id: 'F-61628r1155735_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
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
