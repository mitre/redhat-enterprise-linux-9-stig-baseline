control 'SV-258054' do
  title 'RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

'
  desc 'check', %q(Verify RHEL 9 is configured to lock an account after three unsuccessful logon attempts with the command:

$ grep 'deny =' /etc/security/faillock.conf

deny = 3

If the "deny" option is not set to "3" or less (but not "0"), is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to lock an account when three unsuccessful logon attempts occur.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

deny = 3'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61795r926147_chk'
  tag severity: 'medium'
  tag gid: 'V-258054'
  tag rid: 'SV-258054r926149_rule'
  tag stig_id: 'RHEL-09-411075'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-61719r926148_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
