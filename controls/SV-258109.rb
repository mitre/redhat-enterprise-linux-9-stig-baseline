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
  tag check_id: 'C-61850r926312_chk'
  tag severity: 'medium'
  tag gid: 'V-258109'
  tag rid: 'SV-258109r926314_rule'
  tag stig_id: 'RHEL-09-611100'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-61774r926313_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
