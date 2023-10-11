control 'SV-258189' do
  title 'RHEL 9 must audit all uses of the delete_module system call.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining system calls into one rule whenever possible.

'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "delete_module" system call with the following command:

$ sudo auditctl -l | grep delete_module

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng

If both the "b32" and "b64" audit rules are not defined for the "delete_module" system call, or any of the lines returned are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate an audit event for any successful/unsuccessful use of the "delete_module" system call by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61930r926552_chk'
  tag severity: 'medium'
  tag gid: 'V-258189'
  tag rid: 'SV-258189r926554_rule'
  tag stig_id: 'RHEL-09-654075'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-61854r926553_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
