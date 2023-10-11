control 'SV-258108' do
  title 'RHEL 9 passwords for new users must have a minimum of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.

The DOD minimum password requirement is 15 characters.'
  desc 'check', 'Verify that RHEL 9 enforces a minimum 15-character password length for new user accounts by running the following command:

$ sudo grep -i  pass_min_len /etc/login.defs

PASS_MIN_LEN 15

If the command does not return a "PASS_MIN_LEN" value of "15" or greater, does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce a minimum 15-character password length for new user accounts.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MIN_LEN 15'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61849r926309_chk'
  tag severity: 'medium'
  tag gid: 'V-258108'
  tag rid: 'SV-258108r926311_rule'
  tag stig_id: 'RHEL-09-611095'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-61773r926310_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
