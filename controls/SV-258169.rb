control 'SV-258169' do
  title 'RHEL 9 must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging aids in making sense of who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.

'
  desc 'check', 'Verify that RHEL 9 audit system is configured to resolve audit information before writing to disk, with the following command:

$ sudo grep log_format /etc/audit/auditd.conf

log_format = ENRICHED

If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "log_format" option:

log_format = ENRICHED

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61910r926492_chk'
  tag severity: 'medium'
  tag gid: 'V-258169'
  tag rid: 'SV-258169r926494_rule'
  tag stig_id: 'RHEL-09-653100'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-61834r926493_fix'
  tag satisfies: ['SRG-OS-000255-GPOS-00096', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001487']
  tag nist: ['CM-6 b', 'AU-3 f']
end
