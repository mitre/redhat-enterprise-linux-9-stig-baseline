control 'SV-257889' do
  title 'All RHEL 8 local initialization files must have mode 0740 or less
permissive.'
  desc "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     $ sudo ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the
following command:

    Note: The example will be for the smithj user, who has a home directory of
"/home/smithj".

    $ sudo chmod 0740 /home/smithj/.<INIT_FILE>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230325'
  tag rid: 'SV-257889r917879_rule'
  tag stig_id: 'RHEL-08-010770'
  tag fix_id: 'F-32969r917878_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  ignore_shells = input('non_interactive_shells').join('|')

  homedirs = users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid.zero?) }.homes
  ifiles = command("find #{homedirs.join(' ')} -xdev -maxdepth 1 -name '.*' -type f").stdout.split("\n")

  expected_mode = input('initialization_file_mode')
  failing_files = ifiles.select { |ifile| file(ifile).more_permissive_than?(expected_mode) }

  describe 'All RHEL 8 local initialization files' do
    it "must have mode '#{expected_mode}' or less permissive" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
