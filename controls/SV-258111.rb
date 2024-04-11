control 'SV-258111' do
  title 'RHEL 9 must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'Verify that RHEL 9 enforces password complexity by requiring that at least one uppercase character.

Check the value for "ucredit" with the following command:

$ sudo grep ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf

ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-258111'
  tag rid: 'SV-258111r926320_rule'
  tag stig_id: 'RHEL-09-611110'
  tag fix_id: 'F-61776r926319_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf:' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'ucredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `ucredit` set' do
      expect(value).not_to be_empty, 'ucredit is not set in pwquality.conf'
    end

    it 'only sets `ucredit` once' do
      expect(value.length).to eq(1), 'ucredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `ucredit` to a positive value' do
      expect(value.first.to_i).to cmp < 0, 'ucredit is not set to a negative value in pwquality.conf'
    end
  end
end
