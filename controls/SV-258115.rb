control 'SV-258115' do
  title 'RHEL 9 must require the change of at least four character classes when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the value of the "minclass" option in "/etc/security/pwquality.conf" with the following command:

$ grep minclass /etc/security/pwquality.conf
 
minclass = 4

If the value of "minclass" is set to less than "4", or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

minclass = 4'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-258115'
  tag rid: 'SV-258115r926332_rule'
  tag stig_id: 'RHEL-09-611130'
  tag fix_id: 'F-61780r926331_fix'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
  tag 'host'
  tag 'container'

  value = input('minclass')
  setting = 'minclass'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting_value) { config.params[setting].is_a?(Integer) ? [config.params[setting]] : Array(config.params[setting]) }

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is commented or set more than once in pwquality.conf"
    end

    it "does not set `#{setting}` to more than #{value}" do
      expect(setting_value.first.to_i).to be <= value.to_i, "#{setting} is set to a value greater than #{value} in pwquality.conf"
    end
  end
end
