control 'SV-258095' do
  title 'RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.'
  desc 'If the pam_faillock.so module is not loaded, the system will not correctly lockout accounts to prevent password guessing attacks.'
  desc 'check', 'Verify the pam_faillock.so module is present in the "/etc/pam.d/system-auth" file:

$ grep pam_faillock.so /etc/pam.d/system-auth

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so

If the pam_faillock.so module is not present in the "/etc/pam.d/system-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to include the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.

Add/modify the appropriate sections of the "/etc/pam.d/system-auth" file to match the following lines:
Note: The "preauth" line must be listed before pam_unix.so.

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-258095'
  tag rid: 'SV-258095r958388_rule'
  tag stig_id: 'RHEL-09-611030'
  tag fix_id: 'F-61760r926271_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
    its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
    its('lines') { should match_pam_rule('account required pam_faillock.so') }
  end
end
