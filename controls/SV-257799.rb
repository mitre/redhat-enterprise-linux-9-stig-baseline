control 'SV-257799' do
  title 'RHEL 9 must prevent the loading of a new kernel for later execution.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used subvert the entire secureboot process and should be avoided at all costs especially since it can load unsigned kernel images.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 is configured to disable kernel image loading.

Check the status of the "kernel.kexec_load_disabled" kernel parameter with the following command:

$ sudo sysctl kernel.kexec_load_disabled
kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable kernel image loading.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_kexec_load_disabled.conf

Add the following to the file:
kernel.kexec_load_disabled = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257799'
  tag rid: 'SV-257799r1155697_rule'
  tag stig_id: 'RHEL-09-213020'
  tag fix_id: 'F-61464r1155696_fix'
  tag cci: ['CCI-001749', 'CCI-000366', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-6 b', 'CM-14']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
  }

  parameter = 'kernel.kexec_load_disabled'
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
