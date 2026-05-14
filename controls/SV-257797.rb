control 'SV-257797' do
  title 'RHEL 9 must restrict access to the kernel message buffer.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a nonprivileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 is configured to restrict access to the kernel message buffer.

Check the status of the "kernel.dmesg_restrict" kernel parameter with the following command:

$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to restrict access to the kernel message buffer.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-dmesg_restrict.conf

Add the following to the file:
kernel.dmesg_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-257797'
  tag rid: 'SV-257797r1155691_rule'
  tag stig_id: 'RHEL-09-213010'
  tag fix_id: 'F-61462r1155690_fix'
  tag cci: ['CCI-001090', 'CCI-001082']
  tag nist: ['SC-4', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
  }

  parameter = 'kernel.dmesg_restrict'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

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
