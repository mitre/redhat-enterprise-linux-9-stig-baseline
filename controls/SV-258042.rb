control 'SV-258042' do
  title 'RHEL 8 user account passwords must be configured so that existing
passwords are restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If RHEL 8 does not limit
the lifetime of passwords and force users to change their passwords, there is
the risk that RHEL 8 passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted
to 60 days with the following commands:

    $ sudo awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

    $ sudo awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow

    If any results are returned that are not associated with a system account,
this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 60-day maximum password
lifetime restriction.

    $ sudo chage -M 60 [user]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-230367'
  tag rid: 'SV-258042r627750_rule'
  tag stig_id: 'RHEL-08-020210'
  tag fix_id: 'F-33011r567848_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')

  bad_users = users.where { uid >= 1000 }.where { value > 60 or maxdays.negative? }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Users are not be able' do
    it "to retain passwords for more then #{value} day(s)" do
      failure_message = "The following users can update their password more then every #{value} day(s): #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
