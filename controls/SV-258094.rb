control 'SV-258094' do
  title 'RHEL 9 must not allow blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'Verify that null passwords cannot be used with the following command:

$ sudo grep -i nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If output is produced, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in the "/etc/pam.d/password-auth" and "/etc/pam.d/system-auth" files to prevent logons with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61835r926267_chk'
  tag severity: 'high'
  tag gid: 'V-258094'
  tag rid: 'SV-258094r926269_rule'
  tag stig_id: 'RHEL-09-611025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61759r926268_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
