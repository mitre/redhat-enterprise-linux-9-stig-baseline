control 'SV-257811' do
  title 'RHEL 9 must restrict usage of ptrace to descendant processes.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 restricts the usage of ptrace to descendant processes.

Check the status of the "kernel.yama.ptrace_scope" kernel parameter with the following command:

$ sysctl kernel.yama.ptrace_scope
kernel.yama.ptrace_scope = 1

If the network parameter "kernel.yama.ptrace_scope" is not equal to "1", or nothing is returned, this is a finding.'
  desc 'fix', "Configure RHEL 9 to restrict the usage of ptrace to descendant processes.

Create the drop-in if it doesn't already exist:

$ sudo vi /etc/sysctl.d/99-kernel_yama.ptrace_scope.conf

Add the following line to the file:
kernel.yama.ptrace_scope = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system"
  impact 0.5
  tag check_id: 'C-61552r1155672_chk'
  tag severity: 'medium'
  tag gid: 'V-257811'
  tag rid: 'SV-257811r1155674_rule'
  tag stig_id: 'RHEL-09-213080'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61476r1155673_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001082']
  tag nist: ['CM-6 b', 'SC-2']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.yama.ptrace_scope'
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
