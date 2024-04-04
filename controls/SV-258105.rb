control 'SV-258105' do
  title 'RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime
restriction in /etc/shadow.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, the password could be repeatedly changed in a short period of time to
defeat the organization's policy regarding password reuse."
  desc 'check', %q(Check whether the minimum time period between password changes for each
user account is one day or greater.

    $ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

    If any results are returned that are not associated with a system account,
this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 24 hours/1 day minimum
password lifetime:

    $ sudo chage -m 1 [user]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-230364'
  tag rid: 'SV-258105r627750_rule'
  tag stig_id: 'RHEL-08-020180'
  tag fix_id: 'F-33008r567839_fix'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  # TODO: add inputs for a frequecny

  bad_users = users.where { uid >= 1000 }.where { mindays < 1 }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Users should not' do
    it 'be able to change their password more then once a 24 hour period' do
      failure_message = "The following users can update their password more then once a day: #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
