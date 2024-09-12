control 'SV-258097' do
  title 'RHEL 9 must ensure the password complexity module is enabled in the password-auth file.'
  desc 'Enabling PAM password complexity permits enforcement of strong passwords and consequently makes the system less prone to dictionary attacks.'
  desc 'check', 'Verify RHEL 9 uses "pwquality" to enforce the password complexity rules in the password-auth file with the following command:

$ cat /etc/pam.d/password-auth | grep pam_pwquality

password required pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to use "pwquality" to enforce password complexity rules.

Add the following line to the "/etc/pam.d/password-auth" file (or modify the line to have the required value):

password required pam_pwquality.so'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-258097'
  tag rid: 'SV-258097r997084_rule'
  tag stig_id: 'RHEL-09-611040'
  tag fix_id: 'F-61762r926277_fix'
  tag cci: ['CCI-000192', 'CCI-000366', 'CCI-000193', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['password-auth']) do
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so') }
  end
  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('password (required|requisite) pam_pwquality.so') }
  end
end
