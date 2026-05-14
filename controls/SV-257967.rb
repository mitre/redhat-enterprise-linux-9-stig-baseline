control 'SV-257967' do
  title 'RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.'
  desc 'Some routers will send responses to broadcast frames that violate RFC-1122, which fills up a log file system with many useless error messages. An attacker may take advantage of this and attempt to flood the logs with bogus error logs. Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 limits the number of bogus Internet Control Message Protocol (ICMP) response errors logs.

Check the value of the "net.ipv4.icmp_ignore_bogus_error_response" variables with the following command:

$ sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

If "net.ipv4.icmp_ignore_bogus_error_response" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to not log bogus ICMP errors:

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_icmp_ignore_bogus_error_responses.conf

Add the following line to the file:
net.ipv4.icmp_ignore_bogus_error_responses = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-61708r1155743_chk'
  tag severity: 'medium'
  tag gid: 'V-257967'
  tag rid: 'SV-257967r1155745_rule'
  tag stig_id: 'RHEL-09-253060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61632r1155744_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
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
