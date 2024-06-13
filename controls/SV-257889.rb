control 'SV-257889' do
  title 'All RHEL 9 local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "wadea" user, who has a home directory of "/home/wadea".

$ sudo ls -al /home/wadea/.[^.]* | more

-rwxr-xr-x 1 wadea users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 wadea users 497 Jan 6 2007 .login
-rwxr-xr-x 1 wadea users 886 Jan 6 2007 .something

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the wadea user, who has a home directory of "/home/wadea".

$ sudo chmod 0740 /home/wadea/.<INIT_FILE>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257889'
  tag rid: 'SV-257889r925654_rule'
  tag stig_id: 'RHEL-09-232045'
  tag fix_id: 'F-61554r925653_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  ignore_shells = input('non_interactive_shells').join('|')

  homedirs = users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid.zero?) }.homes
  alternate_ini_file_dirs = input('alternate_ini_file_dirs')
  ifiles = command("find #{homedirs.join(' ')} #{alternate_ini_file_dirs.join(' ')} -xdev -maxdepth 1 -name '.*' -type f -print0").stdout.split("\0")

  exempt_ini_files = input('exempt_ini_files')
  expected_mode = input('initialization_file_mode')
  failing_files = ifiles.select { |ifile| !exempt_ini_files.include?(ifile) && file(ifile).more_permissive_than?(expected_mode) }

  describe 'All RHEL 9 local initialization files' do
    it "must have mode '#{expected_mode}' or less permissive" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
