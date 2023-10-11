control 'SV-258214' do
  title 'Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record.'
  desc 'Misuse of the shutdown command may cause availability issues for the system.'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "shutdown" command with the following command:

$ sudo auditctl -l | grep shutdown

-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "shutdown" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61955r926627_chk'
  tag severity: 'medium'
  tag gid: 'V-258214'
  tag rid: 'SV-258214r926629_rule'
  tag stig_id: 'RHEL-09-654200'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-61879r926628_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
