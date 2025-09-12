control 'SV-258041' do
  title 'RHEL 9 user account passwords for new users or password changes must have a 60-day maximum password lifetime restriction in /etc/login.defs.'
  desc 'Any password, no matter how complex, can eventually be cracked; therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

Setting the password maximum age ensures users are required to periodically change their passwords. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.'
  desc 'check', 'Verify that RHEL 9 enforces a 60-day maximum password lifetime for new user accounts by running the following command:

$ grep -i pass_max_days /etc/login.defs

PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is greater than "60", or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce a 60-day maximum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS 60'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-258041'
  tag rid: 'SV-258041r1038967_rule'
  tag stig_id: 'RHEL-09-411010'
  tag fix_id: 'F-61706r926109_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')
  setting = input_object('pass_max_days').name.upcase

  describe "/etc/login.defs does not have `#{setting}` configured" do
    let(:config) { login_defs.read_params[setting] }
    it "greater than #{value} day" do
      expect(config).to cmp <= value
    end
  end
end
