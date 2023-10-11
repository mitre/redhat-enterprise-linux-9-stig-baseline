control 'SV-258173' do
  title 'RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Allocating an audit_backlog_limit of sufficient size is critical in maintaining a stable boot process. With an insufficient limit allocated, the system is susceptible to boot failures and crashes.

'
  desc 'check', %q(Verify RHEL 9 allocates a sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --info=ALL | grep args | grep -v 'audit_backlog_limit=8192' 

If the command returns any outputs, and audit_backlog_limit is less than "8192", this is a finding.)
  desc 'fix', 'Configure RHEL 9 to allocate sufficient audit_backlog_limit to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args=audit_backlog_limit=8192'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61914r926504_chk'
  tag severity: 'low'
  tag gid: 'V-258173'
  tag rid: 'SV-258173r926506_rule'
  tag stig_id: 'RHEL-09-653120'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-61838r926505_fix'
  tag satisfies: ['SRG-OS-000254-GPOS-00095', 'SRG-OS-000341-GPOS-00132']
  tag 'documentable'
  tag cci: ['CCI-001464', 'CCI-001849']
  tag nist: ['AU-14 (1)', 'AU-4']
end
