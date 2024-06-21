control 'SV-258042' do
  title 'RHEL 9 user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked; therefore, passwords need to be changed periodically. If RHEL 9 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that RHEL 9 passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted to 60 days with the following commands:

$ sudo awk -F: '$5 > 60 {print $1 "" "" $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {print $1 "" "" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure noncompliant accounts to enforce a 60-day maximum password lifetime restriction.

passwd -x 60 [user]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-258042'
  tag rid: 'SV-258042r926113_rule'
  tag stig_id: 'RHEL-09-411015'
  tag fix_id: 'F-61707r926112_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')

  bad_users = users.where { uid >= 1000 }.where { value > 60 or maxdays.negative? }.usernames
  in_scope_users = bad_users - input('home_users_exemptions')

  describe 'Users are not be able' do
    it "to retain passwords for more then #{value} day(s)" do
      failure_message = "The following users can update their password more then every #{value} day(s): #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
