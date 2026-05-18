control 'SV-257816' do
  title 'RHEL 9 must disable the use of user namespaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 9 disables the use of user namespaces.

Check the status of the "user.max_user_namespaces" parameter with the following command:

$ sudo sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If "user.max_user_namespaces" is not set to "0" or is missing, this is a finding.

If the use of namespaces is operationally required and documented with the information system security manager (ISSM), it is not a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the use of user namespaces.

Create the drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-user_max_user_namespaces.conf

Add the following line to the file:

user.max_user_namespaces = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257816'
  tag rid: 'SV-257816r1155715_rule'
  tag stig_id: 'RHEL-09-213105'
  tag fix_id: 'F-61481r1155714_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('user_namespaces_documented') == true
    describe 'User namespaces ISSM approval/documentation' do
      it 'is present' do
        expect(input('user_namespaces_documented')).to eq true
      end
    end
  else
    parameter = 'user.max_user_namespaces'
    value = 0
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
end
