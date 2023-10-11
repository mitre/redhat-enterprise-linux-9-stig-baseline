control 'SV-258107' do
  title 'RHEL 9 passwords must be created with a minimum of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.

RHEL 9 uses "pwquality" as a mechanism to enforce password complexity. Configurations are set in the "etc/security/pwquality.conf" file.

The "minlen", sometimes noted as minimum length, acts as a "score" of complexity based on the credit components of the "pwquality" module. By setting the credit components to a negative value, not only will those components be required, but they will not count toward the total "score" of "minlen". This will enable "minlen" to require a 15-character minimum.

The DOD minimum password requirement is 15 characters.'
  desc 'check', 'Verify that RHEL 9 enforces a minimum 15-character password length with the following command:

$ grep minlen /etc/security/pwquality.conf

minlen = 15

If the command does not return a "minlen" value of "15" or greater, does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce a minimum 15-character password length.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

minlen = 15'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61848r926306_chk'
  tag severity: 'medium'
  tag gid: 'V-258107'
  tag rid: 'SV-258107r926308_rule'
  tag stig_id: 'RHEL-09-611090'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-61772r926307_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
