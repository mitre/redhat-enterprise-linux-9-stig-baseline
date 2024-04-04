control 'SV-257975' do
  title 'RHEL 9 must not accept router advertisements on all IPv6 interfaces by default.'
  desc 'An illicit router advertisement message could result in a man-in-the-middle attack.'
  desc 'check', %q(Verify RHEL 9 does not accept router advertisements on all IPv6 interfaces by default, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Determine if router advertisements are not accepted by default by using the following command:

$ sudo sysctl net.ipv6.conf.default.accept_ra

net.ipv6.conf.default.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F net.ipv6.conf.default.accept_ra | tail -1

net.ipv6.conf.default.accept_ra = 0

If "net.ipv6.conf.default.accept_ra" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not accept router advertisements on all IPv6 interfaces by default unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_ra = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257975'
  tag rid: 'SV-257975r943007_rule'
  tag stig_id: 'RHEL-09-254030'
  tag fix_id: 'F-61640r925911_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'net.ipv6.conf.default.accept_ra'
  action = 'IPv6 router advertisements (by default for all interfaces)'
  value = 0

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('ipv6_enabled') == false
    impact 0.0
    describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
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
