control 'SV-258055' do
  title 'RHEL 9 must automatically lock the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, also known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Verify RHEL 9 is configured to lock the root account after three unsuccessful logon attempts with the command:

$ grep even_deny_root /etc/security/faillock.conf

even_deny_root

If the "even_deny_root" option is not set, is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to lock out the "root" account after a number of incorrect login attempts using "pam_faillock.so", first enable the feature using the following command:
 
$ sudo authselect enable-feature with-faillock  

 Then edit the "/etc/security/faillock.conf" file as follows:
 
  add or uncomment the following line:
 even_deny_root'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61796r926150_chk'
  tag severity: 'medium'
  tag gid: 'V-258055'
  tag rid: 'SV-258055r926152_rule'
  tag stig_id: 'RHEL-09-411080'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-61720r926151_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
