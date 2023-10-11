control 'SV-258091' do
  title 'RHEL 9 must ensure the password complexity module in the system-auth file is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 9 uses "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth

By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Verify RHEL 9 is configured to limit the "pwquality" retry option to "3". 

Check for the use of the "pwquality" retry option in the system-auth file with the following command:

$ cat /etc/pam.d/system-auth | grep pam_pwquality

password required pam_pwquality.so retry=3

If the value of "retry" is set to "0" or greater than "3", or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to limit the "pwquality" retry option to "3".

Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

password required pam_pwquality.so retry=3'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61832r926258_chk'
  tag severity: 'medium'
  tag gid: 'V-258091'
  tag rid: 'SV-258091r926260_rule'
  tag stig_id: 'RHEL-09-611010'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-61756r926259_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
