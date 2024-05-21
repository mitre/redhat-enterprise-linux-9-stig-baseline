control 'SV-258109' do
  title 'RHEL 9 must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. RHEL 9 utilizes "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".'
  desc 'check', 'Verify that RHEL 9 enforces password complexity by requiring at least one special character with the following command:

$ sudo grep ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf

ocredit = -1

If the value of "ocredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce password complexity by requiring at least one special character be used by setting the "ocredit" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

ocredit = -1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-258109'
  tag rid: 'SV-258109r926314_rule'
  tag stig_id: 'RHEL-09-611100'
  tag fix_id: 'F-61774r926313_fix'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  # value = input('ocredit')
  setting = 'ocredit'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting_value) { config.params[setting].is_a?(Integer) ? [config.params[setting]] : Array(config.params[setting]) }

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is commented or set more than once in pwquality.conf"
    end

    it "does not set `#{setting}` to a positive value" do
      expect(setting_value.first.to_i).to be <= 0, "#{setting} is set to a positive value in pwquality.conf"
    end
  end
end
