control 'SV-257803' do
  title 'RHEL 9 must disable the kernel.core_pattern.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', %q(Verify RHEL 9 disables storing core dumps with the following commands:

$ sudo sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to disable core dump storage.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.core_pattern | tail -1

kernel.core_pattern = |/bin/false

If "kernel.core_pattern" is not set to "|/bin/false" and is not documented with the ISSO as an operational requirement, or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to disable storing core dumps.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.core_pattern = |/bin/false

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257803'
  tag rid: 'SV-257803r942973_rule'
  tag stig_id: 'RHEL-09-213040'
  tag fix_id: 'F-61468r925395_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  kernel_setting = 'kernel.core_pattern'
  kernel_expected_value = input('kernel_dump_expected_value')

  describe kernel_parameter(kernel_setting) do
    its('value') { should eq kernel_expected_value }
  end

  k_conf_files = input('sysctl_conf_files')

  # make sure the setting is set somewhere
  k_conf = command("grep -r #{kernel_setting} #{k_conf_files.join(' ')}").stdout.split("\n")

  # make sure it is set correctly
  failing_k_conf = k_conf.reject { |k| k.match(/#{kernel_parameter}\s*=\s*#{kernel_expected_value}/) }

  describe 'Kernel config files' do
    it "should set '#{kernel_setting}' on startup" do
      expect(k_conf).to_not be_empty, "Setting not found in any of the following config files:\n\t- #{k_conf_files.join("\n\t- ")}"
      expect(failing_k_conf).to be_empty, "Incorrect or conflicting settings found:\n\t- #{failing_k_conf.join("\n\t- ")}" unless k_conf.empty?
    end
  end
end
