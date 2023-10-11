control 'SV-258226' do
  title 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/tallylog.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

'
  desc 'check', 'Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/tallylog" with the following command:

$ sudo auditctl -l | grep /var/log/tallylog

-w /var/log/tallylog -p wa -k logins

If the command does not return a line, or the line is commented out, is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/tallylog".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/tallylog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61967r926663_chk'
  tag severity: 'medium'
  tag gid: 'V-258226'
  tag rid: 'SV-258226r926665_rule'
  tag stig_id: 'RHEL-09-654260'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-61891r926664_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
end
