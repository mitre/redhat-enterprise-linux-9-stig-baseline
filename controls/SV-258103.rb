control 'SV-258103' do
  title 'RHEL 9 must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'Verify that RHEL 9 enforces password complexity by requiring at least one numeric character.

Check the value for "dcredit" with the following command:

$ sudo grep dcredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf

/etc/security/pwquality.conf:dcredit = -1 

If the value of "dcredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce password complexity by requiring at least one numeric character be used by setting the "dcredit" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

dcredit = -1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61844r926294_chk'
  tag severity: 'medium'
  tag gid: 'V-258103'
  tag rid: 'SV-258103r926296_rule'
  tag stig_id: 'RHEL-09-611070'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-61768r926295_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
