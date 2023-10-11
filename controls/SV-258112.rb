control 'SV-258112' do
  title 'RHEL 9 must require the change of at least eight characters when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute–force attacks. 

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. Requiring a minimum number of different characters during password changes ensures that newly changed passwords will not resemble previously compromised ones. Note that passwords changed on compromised systems will still be compromised.'
  desc 'check', 'Verify the value of the "difok" option in "/etc/security/pwquality.conf" with the following command:

$ sudo grep difok /etc/security/pwquality.conf

difok = 8
 
If the value of "difok" is set to less than "8", or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

difok = 8'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61853r926321_chk'
  tag severity: 'medium'
  tag gid: 'V-258112'
  tag rid: 'SV-258112r926323_rule'
  tag stig_id: 'RHEL-09-611115'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-61777r926322_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
