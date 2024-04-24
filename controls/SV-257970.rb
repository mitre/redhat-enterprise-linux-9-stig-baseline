control 'SV-257970' do
  title 'RHEL 9 must not enable IPv4 packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this capability is used when not required, system network information may be unnecessarily transmitted across the network.'
  desc 'check', %q(Verify RHEL 9 is not performing IPv4 packet forwarding, unless the system is a router.

Check that IPv4 forwarding is disabled using the following command:

$ sudo sysctl net.ipv4.conf.all.forwarding

net.ipv4.conf.all.forwarding = 0

If the IPv4 forwarding value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo (/usr/lib/systemd/systemd-sysctl --cat-config; cat /etc/sysctl.conf) | egrep -v '^(#|$)' | grep net.ipv4.conf.all.forwarding | tail -1

net.ipv4.conf.all.forwarding = 0

If "net.ipv4.conf.all.forwarding" is not set to "0" and is not documented with the ISSO as an operational requirement or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not allow IPv4 packet forwarding, unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.forwarding = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61711r943000_chk'
  tag severity: 'medium'
  tag gid: 'V-257970'
  tag rid: 'SV-257970r943001_rule'
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

  # Define the kernel parameter to be checked
  parameter = 'net.ipv4.conf.all.forwarding'
  action = 'IPv4 packet forwarding'
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
      it 'is correctly set in the active kernel parameters' do
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
