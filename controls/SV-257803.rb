control 'SV-257803' do
  title 'RHEL 8 must disable the kernel.core_pattern.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 disables storing core dumps with the following commands:

$ sudo sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.core_pattern /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.core_pattern = |/bin/false

If "kernel.core_pattern" is not set to "|/bin/false", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable storing core dumps.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.core_pattern = |/bin/false

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230311'
  tag rid: 'SV-257803r858769_rule'
  tag stig_id: 'RHEL-08-010671'
  tag fix_id: 'F-32955r858768_fix'
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

  k_conf_files = input('kernel_config_files')

  # make sure the setting is set somewhere
  k_conf = command("grep -r #{kernel_setting} #{k_conf_files.join(' ')}").stdout.split("\n")

  # make sure it is set correctly
  failing_k_conf = k_conf.reject { |k| k.match(/#{kernel_parameter}\s*=\s*#{kernel_expected_value}/) }

  describe 'Kernel config files' do
    it "should set '#{kernel_setting}' on startup" do
      expect(k_conf).to_not be_empty, "Setting not found in any of the following config files:\n\t- #{k_conf_files.join("\n\t- ")}"
      expect(failing_k_conf).to be_empty, "Incorrect or conflicting settings found:\n\t- #{failing_k_conf.join("\n\t- ")}" if k_conf.nil?
    end
  end
end
