control 'SV-258101' do
  title 'RHEL 9 must enforce password complexity rules for the root account.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'Verify that RHEL 9 enforces password complexity rules for the root account.

Check if root user is required to use complex passwords with the following command:

$ grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf

/etc/security/pwquality.conf:enforce_for_root

If "enforce_for_root" is commented or missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce password complexity on the root account.

Add or update the following line in /etc/security/pwquality.conf:

enforce_for_root'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61842r926288_chk'
  tag severity: 'medium'
  tag gid: 'V-258101'
  tag rid: 'SV-258101r926290_rule'
  tag stig_id: 'RHEL-09-611060'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-61766r926289_fix'
  tag satisfies: ['SRG-OS-000072-GPOS-00040', 'SRG-OS-000071-GPOS-00039', 'SRG-OS-000070-GPOS-00038', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000078-GPOS-00046', 'SRG-OS-000480-GPOS-00225', 'SRG-OS-000069-GPOS-00037']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-000366', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (a)', 'CM-6 b', 'IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  # TODO: use this pattern on the rest of the pwquality.conf settings (current implementation for the other ones dont account for multiple conf files)

  setting = 'enforce_for_root'

  # Note: -s to supress if no files
  # Note: -h to just have occurances and ignore filename
  setting_check = command("grep -sh #{setting} /etc/security/pwquality.conf /etc/security/pwquality.conf/*").stdout.strip.match(/^#{setting}$/)
  describe 'The root account' do
    it 'should enforce password complexity rules' do
      expect(setting_check).to_not be_nil, "'#{setting}' not found (or commented out) in conf file(s)"
      expect(setting_check.length).to eq(1), "'#{setting}' set more than once in conf file(s)"
    end
  end
end
