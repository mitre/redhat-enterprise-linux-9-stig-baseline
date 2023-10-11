control 'SV-258041' do
  title 'RHEL 9 user account passwords for new users or password changes must have a 60-day maximum password lifetime restriction in /etc/login.defs.'
  desc 'Any password, no matter how complex, can eventually be cracked; therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

Setting the password maximum age ensures users are required to periodically change their passwords. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.'
  desc 'check', 'Verify that RHEL 9 enforces a 60-day maximum password lifetime for new user accounts by running the following command:

$ grep -i pass_max_days /etc/login.defs

PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is greater than "60", or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce a 60-day maximum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS 60'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61782r926108_chk'
  tag severity: 'medium'
  tag gid: 'V-258041'
  tag rid: 'SV-258041r926110_rule'
  tag stig_id: 'RHEL-09-411010'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-61706r926109_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
