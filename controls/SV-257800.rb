control 'SV-257800' do
  title 'RHEL 9 must restrict exposed kernel pointer addresses access.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 is configured to restrict exposed kernel pointer address access.

Verify the runtime status of the "kernel.kptr_restrict" kernel parameter with the following command:

$ sudo sysctl kernel.kptr_restrict
kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to restrict exposed kernel pointer addresses access.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_kptr_restrict.conf

Add the following to the file:
kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag gid: 'V-257800'
  tag rid: 'SV-257800r1155700_rule'
  tag stig_id: 'RHEL-09-213025'
  tag fix_id: 'F-61465r1155699_fix'
  tag cci: ['CCI-000366', 'CCI-001082', 'CCI-002824']
  tag nist: ['CM-6 b', 'SC-2', 'SI-16']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.kptr_restrict'
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
