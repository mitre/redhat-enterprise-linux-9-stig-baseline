control 'SV-258060' do
  title 'RHEL 9 must ensure account lockouts persist.'
  desc 'Having lockouts persist across reboots ensures that account is only unlocked by an administrator. If the lockouts did not persist across reboots, an attacker could simply reboot the system to continue brute force attacks against the accounts on the system.'
  desc 'check', %q(Verify the "/etc/security/faillock.conf" file is configured use a nondefault faillock directory to ensure contents persist after reboot with the following command:

$ grep 'dir =' /etc/security/faillock.conf

dir = /var/log/faillock

If the "dir" option is not set to a nondefault documented tally log directory, is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 maintain the contents of the faillock directory after a reboot.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

dir = /var/log/faillock'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61801r926165_chk'
  tag severity: 'medium'
  tag gid: 'V-258060'
  tag rid: 'SV-258060r926167_rule'
  tag stig_id: 'RHEL-09-411105'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-61725r926166_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
