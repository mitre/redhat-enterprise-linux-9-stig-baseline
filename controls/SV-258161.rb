control 'SV-258161' do
  title 'RHEL 9 must label all offloaded audit logs before sending them to the central log server.'
  desc 'Enriched logging is needed to determine who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.

When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

'
  desc 'check', 'Verify that RHEL 9 Audit Daemon is configured to label all offloaded audit logs, with the following command:

$ sudo grep name_format /etc/audit/auditd.conf

name_format = hostname

If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "name_format" option:

name_format = hostname

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61902r926468_chk'
  tag severity: 'medium'
  tag gid: 'V-258161'
  tag rid: 'SV-258161r926470_rule'
  tag stig_id: 'RHEL-09-653060'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-61826r926469_fix'
  tag satisfies: ['SRG-OS-000039-GPOS-00017', 'SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-000132', 'CCI-001851']
  tag nist: ['AU-3 c', 'AU-4 (1)']
end
