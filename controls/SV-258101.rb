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
end
