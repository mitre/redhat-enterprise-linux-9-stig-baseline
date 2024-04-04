control 'SV-257800' do
  title 'RHEL 9 must restrict exposed kernel pointer addresses access.'
  desc 'Exposing kernel pointers (through procfs or "seq_printf()") exposes kernel writeable structures, which may contain functions pointers. If a write vulnerability occurs in the kernel, allowing write access to any of this structure, the kernel can be compromised. This option disallows any program without the CAP_SYSLOG capability to get the addresses of kernel pointers by replacing them with "0".'
  desc 'check', %q(Verify the runtime status of the kernel.kptr_restrict kernel parameter with the following command:

$ sudo sysctl kernel.kptr_restrict 

kernel.kptr_restrict = 1

Verify the configuration of the kernel.kptr_restrict kernel parameter with the following command:

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F kernel.kptr_restrict | tail -1

kernel.kptr_restrict =1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-257800'
  tag rid: 'SV-257800r942971_rule'
  tag stig_id: 'RHEL-09-213025'
  tag fix_id: 'F-61465r925386_fix'
  tag cci: ['CCI-000366', 'CCI-001082', 'CCI-002824']
  tag nist: ['CM-6 b', 'SC-2', 'SI-16']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'kernel.kptr_restrict'
  action = 'kernel pointer addresses'
  value = 1

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
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
