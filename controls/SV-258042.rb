control 'SV-258042' do
  title 'RHEL 9 user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked; therefore, passwords need to be changed periodically. If RHEL 9 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that RHEL 9 passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted to 60 days with the following commands:

$ sudo awk -F: '$5 > 60 {print $1 "" "" $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {print $1 "" "" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure noncompliant accounts to enforce a 60-day maximum password lifetime restriction.

passwd -x 60 [user]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61783r926111_chk'
  tag severity: 'medium'
  tag gid: 'V-258042'
  tag rid: 'SV-258042r926113_rule'
  tag stig_id: 'RHEL-09-411015'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-61707r926112_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
