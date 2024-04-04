control 'SV-257969' do
  title 'RHEL 8 must not allow interfaces to perform Internet Control Message
Protocol (ICMP) redirects by default.'
  desc %q(ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). There is only a directive to disable sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf)
  desc 'check', 'Verify RHEL 8 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.send_redirects = 0

If "net.ipv4.conf.default.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230543'
  tag rid: 'SV-257969r858816_rule'
  tag stig_id: 'RHEL-08-040270'
  tag fix_id: 'F-33187r858815_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'net.ipv4.conf.default.send_redirects'
  action = 'IPv4 packet redirects for interfaces'
  value = 0

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    describe kernel_parameter(parameter) do
      it 'is disabled in sysctl -a' do
        expect(current_value.value).to cmp value
        expect(current_value.value).not_to be_nil
      end
    end

    # Get the list of sysctl configuration files
    sysctl_config_files = input('sysctl_conf_files').map(&:strip).join(' ')

    # Search for the kernel parameter in the configuration files
    search_results = command("grep -r #{parameter} #{sysctl_config_files} {} \;").stdout.split("\n")

    # Parse the search results into a hash
    config_values = search_results.each_with_object({}) do |item, results|
      file, setting = item.split(':')
      results[file] ||= []
      results[file] << setting.split('=').last
    end

    uniq_config_values = config_values.values.flatten.map(&:strip).map(&:to_i).uniq

    # Check the configuration files
    describe 'Configuration files' do
      if search_results.empty?
        it "do not explicitly set the `#{parameter}` parameter" do
          expect(config_values).not_to be_empty, "Add the line `#{parameter}=#{value}` to a file in the `/etc/sysctl.d/` directory"
        end
      else
        it "do not have conflicting settings for #{action}" do
          expect(uniq_config_values.count).to eq(1), "Expected one unique configuration, but got #{config_values}"
        end
        it "set the parameter to the right value for #{action}" do
          expect(config_values.values.flatten.all? { |v| v.to_i.eql?(value) }).to be true
        end
      end
    end
  end
end
