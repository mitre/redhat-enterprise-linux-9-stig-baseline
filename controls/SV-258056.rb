control 'SV-258056' do
  title 'RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Verify RHEL 9 locks an account after three unsuccessful logon attempts within a period of 15 minutes with the following command:

Note: If the system administrator demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is Not Applicable.

$ grep fail_interval /etc/security/faillock.conf 

fail_interval = 900

If the "fail_interval" option is not set to "900" or less (but not "0"), the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'To configure RHEL 9 to lock out the "root" account after a number of incorrect login attempts within 15 minutes using "pam_faillock.so", enable the feature using the following command:
 
$ authselect enable-feature with-faillock  

Then edit the "/etc/security/faillock.conf" file as follows:

fail_interval = 900'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61797r926153_chk'
  tag severity: 'medium'
  tag gid: 'V-258056'
  tag rid: 'SV-258056r926155_rule'
  tag stig_id: 'RHEL-09-411085'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-61721r926154_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
