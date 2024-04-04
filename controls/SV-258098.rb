control 'SV-258098' do
  title 'RHEL 8 must ensure the password complexity module is enabled in the system-auth file.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 8 uses "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth'
  desc 'check', 'Verify the operating system uses "pwquality" to enforce the password complexity rules.

Check for the use of "pwquality" in the system-auth file with the following command:

     $ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

     password requisite pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so" as shown, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to use "pwquality" to enforce password complexity rules.

Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

     password requisite pam_pwquality.so'
  impact 0.5
  tag check_id: 'C-55150r902738_chk'
  tag severity: 'medium'
  tag gid: 'V-251713'
  tag rid: 'SV-258098r902740_rule'
  tag stig_id: 'RHEL-08-020101'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55104r902739_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  [pam_auth_files['password-auth'], pam_auth_files['system-auth']].each do |path|
    describe pam(path) do
      its('lines') { should match_pam_rule('.* .* pam_pwquality.so') }
    end
  end
end
