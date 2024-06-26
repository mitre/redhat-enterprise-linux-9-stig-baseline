control 'SV-258098' do
  title 'RHEL 9 must ensure the password complexity module is enabled in the system-auth file.'
  desc 'Enabling PAM password complexity permits enforcement of strong passwords and consequently makes the system less prone to dictionary attacks.'
  desc 'check', 'Verify RHEL 9 uses "pwquality" to enforce the password complexity rules in the system-auth file with the following command:

$ cat /etc/pam.d/system-auth | grep pam_pwquality

password required pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to use "pwquality" to enforce password complexity rules.

Add the following line to the "/etc/pam.d/system-auth" file(or modify the line to have the required value):

password required pam_pwquality.so'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61839r926279_chk'
  tag severity: 'medium'
  tag gid: 'V-258098'
  tag rid: 'SV-258098r926281_rule'
  tag stig_id: 'RHEL-09-611045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61763r926280_fix'
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
