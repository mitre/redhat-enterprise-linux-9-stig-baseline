control 'SV-258057' do
  title 'RHEL 9 must maintain an account lock until the locked account is released by an administrator.'
  desc 'By limiting the number of failed logon attempts the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', %q(Verify RHEL 9 is configured to lock an account until released by an administrator after three unsuccessful logon attempts with the command:

$ grep 'unlock_time =' /etc/security/faillock.conf

unlock_time = 0

If the "unlock_time" option is not set to "0", the line is missing, or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to lock an account until released by an administrator after three unsuccessful logon attempts with the command:
 
$ authselect enable-feature with-faillock  

Then edit the "/etc/security/faillock.conf" file as follows:

unlock_time = 0'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61798r926156_chk'
  tag severity: 'medium'
  tag gid: 'V-258057'
  tag rid: 'SV-258057r926158_rule'
  tag stig_id: 'RHEL-09-411090'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-61722r926157_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
