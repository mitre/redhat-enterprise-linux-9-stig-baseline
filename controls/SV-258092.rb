control 'SV-258092' do
  title 'RHEL 9 must be configured in the password-auth file to prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

RHEL 9 uses "pwhistory" consecutively as a mechanism to prohibit password reuse. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth

Note that manual changes to the listed files may be overwritten by the "authselect" program.'
  desc 'check', 'Verify RHEL 9 is configured in the password-auth file to prohibit password reuse for a minimum of five generations with the following command:

$ grep -i remember /etc/pam.d/password-auth

password required pam_pwhistory.so use_authtok remember=5 retry=3

If the line containing "pam_pwhistory.so" does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure the RHEL 9 password-auth file to prohibit password reuse for a minimum of five generations.

Add the following line in "/etc/pam.d/password-auth" (or modify the line to have the required value):

password required pam_pwhistory.so use_authtok remember=5 retry=3'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61833r926261_chk'
  tag severity: 'medium'
  tag gid: 'V-258092'
  tag rid: 'SV-258092r926263_rule'
  tag stig_id: 'RHEL-09-611015'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-61757r926262_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
