control 'SV-257797' do
  title 'RHEL 8 must restrict access to the kernel message buffer.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a non-privileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify the operating system is configured to restrict access to the kernel message buffer with the following commands:

Check the status of the kernel.dmesg_restrict kernel parameter.

$ sudo sysctl kernel.dmesg_restrict

kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to restrict access to the kernel message buffer.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-230269'
  tag rid: 'SV-257797r858756_rule'
  tag stig_id: 'RHEL-08-010375'
  tag fix_id: 'F-32913r858755_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  action = 'kernel.dmesg_restrict'

  describe kernel_parameter(action) do
    its('value') { should eq 1 }
  end

  search_result = command("grep -r ^#{action} #{input('sysctl_conf_files').join(' ')}").stdout.strip

  correct_result = search_result.lines.any? { |line| line.match(/#{action}\s*=\s*1$/) }
  incorrect_results = search_result.lines.map(&:strip).select { |line| line.match(/#{action}\s*=\s*[^1]$/) }

  describe 'Kernel config files' do
    it "should configure '#{action}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
