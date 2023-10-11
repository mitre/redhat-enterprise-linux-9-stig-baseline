control 'SV-258224' do
  title 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

'
  desc 'check', 'Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock" with the following command:

$ sudo auditctl -l | grep /var/log/faillock

-w /var/log/faillock -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/faillock".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/faillock -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61965r926657_chk'
  tag severity: 'medium'
  tag gid: 'V-258224'
  tag rid: 'SV-258224r926659_rule'
  tag stig_id: 'RHEL-09-654250'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-61889r926658_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
end
