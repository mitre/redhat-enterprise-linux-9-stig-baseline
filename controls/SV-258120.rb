control 'SV-258120' do
  title 'The RHEL 8 operating system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.)
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account
with the following commands:

Perform a password reset:
$ sudo passwd [username]

Lock an account:
$ sudo passwd -l [username]'
  impact 0.7
  tag check_id: 'C-55143r809340_chk'
  tag severity: 'high'
  tag gid: 'V-251706'
  tag rid: 'SV-258120r809342_rule'
  tag stig_id: 'RHEL-08-010121'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55097r809341_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  users_with_blank_passwords = shadow.where { password.nil? || password.empty? }.users - input('users_allowed_blank_passwords')

  describe 'All users' do
    it 'should have a password set' do
      fail_msg = "Users with blank passwords:\n\t- #{users_with_blank_passwords.join("\n\t- ")}"
      expect(users_with_blank_passwords).to be_empty, fail_msg
    end
  end
end
