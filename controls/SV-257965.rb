control 'SV-257965' do
  title 'RHEL 9 must use a reverse-path filter for IPv4 network traffic when possible by default.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks, but is helpful for end hosts and routers serving small networks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 uses reverse path filtering on IPv4 interfaces.

Check the value of the "net.ipv4.conf.default.rp_filter" with the following command:

$ sudo sysctl net.ipv4.conf.default.rp_filter
net.ipv4.conf.default.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to use reverse path filtering on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_rp_filter.conf

Add the following line to the file:
net.ipv4.conf.default.rp_filter = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-61706r1155644_chk'
  tag severity: 'medium'
  tag gid: 'V-257965'
  tag rid: 'SV-257965r1155646_rule'
  tag stig_id: 'RHEL-09-253050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61630r1155645_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'net.ipv4.conf.default.rp_filter'
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
