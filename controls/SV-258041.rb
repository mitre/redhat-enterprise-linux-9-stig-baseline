control 'SV-258041' do
  title 'RHEL 8 user account passwords must have a 60-day maximum password
lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If RHEL 8 does not limit
the lifetime of passwords and force users to change their passwords, there is
the risk that RHEL 8 passwords could be compromised.'
  desc 'check', 'Verify that RHEL 8 enforces a 60-day maximum password lifetime for new user
accounts by running the following command:

    $ sudo grep -i pass_max_days /etc/login.defs
    PASS_MAX_DAYS 60

    If the "PASS_MAX_DAYS" parameter value is greater than "60", or
commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enforce a 60-day maximum password lifetime.

Add, or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS 60'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-230366'
  tag rid: 'SV-258041r646878_rule'
  tag stig_id: 'RHEL-08-020200'
  tag fix_id: 'F-33010r567845_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
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
