control 'SV-258096' do
  title 'RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.'
  desc 'If the pam_faillock.so module is not loaded, the system will not correctly lockout accounts to prevent password guessing attacks.'
  desc 'check', 'Verify the pam_faillock.so module is present in the "/etc/pam.d/password-auth" file:

$ grep pam_faillock.so /etc/pam.d/password-auth

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so

If the pam_faillock.so module is not present in the "/etc/pam.d/password-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to include the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.

Add/modify the appropriate sections of the "/etc/pam.d/password-auth" file to match the following lines:
Note: The "preauth" line must be listed before pam_unix.so.

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61837r926273_chk'
  tag severity: 'medium'
  tag gid: 'V-258096'
  tag rid: 'SV-258096r926275_rule'
  tag stig_id: 'RHEL-09-611035'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-61761r926274_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
