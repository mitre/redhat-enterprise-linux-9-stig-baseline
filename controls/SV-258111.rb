control 'SV-258111' do
  title 'RHEL 8 must enforce password complexity by requiring that at least one
uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require uppercase characters, without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".'
  desc 'check', 'Verify the value for "ucredit" with the following command:

$ sudo grep -r ucredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-230357'
  tag rid: 'SV-258111r858771_rule'
  tag stig_id: 'RHEL-08-020110'
  tag fix_id: 'F-33001r858770_fix'
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
