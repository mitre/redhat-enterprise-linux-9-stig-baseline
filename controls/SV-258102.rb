control 'SV-258102' do
  title 'RHEL 8 must enforce password complexity by requiring that at least one
lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require lower-case characters without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".'
  desc 'check', 'Verify the value for "lcredit" with the following command:

$ sudo grep -r lcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:lcredit = -1

If the value of "lcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one lower-case character be used by setting the "lcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

lcredit = -1

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag gid: 'V-230358'
  tag rid: 'SV-258102r858773_rule'
  tag stig_id: 'RHEL-08-020120'
  tag fix_id: 'F-33002r858772_fix'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'lcredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `lcredit` set' do
      expect(value).not_to be_empty, 'lcredit is not set in pwquality.conf'
    end

    it 'only sets `lcredit` once' do
      expect(value.length).to eq(1), 'lcredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `lcredit` to a positive value' do
      expect(value.first.to_i).to be < 0, 'lcredit is not set to a negative value in pwquality.conf'
    end
  end
end
