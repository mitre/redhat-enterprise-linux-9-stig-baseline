control 'SV-258044' do
  title 'RHEL 9 must set the umask value to 077 for all local interactive user accounts.'
  desc 'The umask controls the default access mode assigned to newly created
files. A umask of 077 limits new files to mode 600 or less permissive. Although
umask can be represented as a four-digit number, the first digit representing
special access modes is typically ignored or required to be "0". This
requirement applies to the globally configured system defaults and the local
interactive user defaults for each account on the system.'
  desc 'check', 'Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

# grep -ri umask /home/

/home/wadea/.bash_history:grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile
/home/wadea/.bash_history:grep -i umask /etc/login.defs

If any local interactive user initialization files are found to have a umask statement that sets a value less restrictive than "077", this is a finding.'
  desc 'fix', %q(Remove the umask statement from all local interactive user's initialization files.

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the information system security officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account's environment variables.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258044'
  tag rid: 'SV-258044r926119_rule'
  tag stig_id: 'RHEL-09-411025'
  tag fix_id: 'F-61709r926118_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  exempt_home_users = input('exempt_home_users')
  expected_mode = input('permissions_for_shells')['default_umask']
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iusers = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iusers.users.nil? && !iusers.users.empty?

    # run the check text's grep against all interactive users, compare any hits to the expected mode
    failing_users = iusers.entries.select { |u|
      umask_set = command("grep -ir ^umask #{u.home} | grep -v '.bash_history'").stdout.strip
      umask_set.nil? && umask_set.match(/(?<umask>\d{3,4})/)['umask'].to_i > expected_mode.to_i
    }.map(&:user)

    describe 'All non-exempt interactive users on the system' do
      it "should not set the UMASK more permissive than '#{expected_mode}' in any init files" do
        expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
