control 'SV-258102' do
  title 'RHEL 9 must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Requiring a minimum number of lowercase characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'Verify that RHEL 9 enforces password complexity by requiring at least one lowercase character.

Check the value for "lcredit" with the following command:

$ sudo grep lcredit /etc/security/pwquality.conf /etc/security/pwquality.conf/*.conf 

/etc/security/pwquality.conf:lcredit = -1 

If the value of "lcredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce password complexity by requiring at least one lowercase character be used by setting the "lcredit" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

lcredit = -1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61843r926291_chk'
  tag severity: 'medium'
  tag gid: 'V-258102'
  tag rid: 'SV-258102r926293_rule'
  tag stig_id: 'RHEL-09-611065'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-61767r926292_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
