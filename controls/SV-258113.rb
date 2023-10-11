control 'SV-258113' do
  title 'RHEL 9 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the value of the "maxclassrepeat" option in "/etc/security/pwquality.conf" with the following command:

$ grep maxclassrepeat /etc/security/pwquality.conf 

maxclassrepeat = 4

If the value of "maxclassrepeat" is set to "0", more than "4", or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option.

Add the following line to "/etc/security/pwquality.conf" conf (or modify the line to have the required value):

maxclassrepeat = 4'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61854r926324_chk'
  tag severity: 'medium'
  tag gid: 'V-258113'
  tag rid: 'SV-258113r926326_rule'
  tag stig_id: 'RHEL-09-611120'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-61778r926325_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
