control 'SV-258104' do
  title 'RHEL 9 passwords for new users or password changes must have a 24 hours minimum password lifetime restriction in /etc/login.defs.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement."
  desc 'check', 'Verify RHEL 9 enforces 24 hours as the minimum password lifetime for new user accounts.

Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command: 

$ grep -i pass_min_days /etc/login.defs

PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce 24 hours as the minimum password lifetime.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MIN_DAYS 1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61845r926297_chk'
  tag severity: 'medium'
  tag gid: 'V-258104'
  tag rid: 'SV-258104r926299_rule'
  tag stig_id: 'RHEL-09-611075'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-61769r926298_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
